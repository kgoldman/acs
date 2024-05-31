/********************************************************************************/
/*										*/
/*			TPM 2.0 Attestation - Common Crypto	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2024.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "openssl/pem.h"
#include <openssl/aes.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscrypto.h>
#include "ekutils.h"
#include "cryptoutils.h"

#include "commonerror.h"

#include "commoncrypto.h"

extern int verbose;
extern int vverbose;

/* convertX509DerToPem() converts an OpenSSL DER stream to PEM format stream */

TPM_RC convertX509DerToPem(char **pemString,	/* freed by caller */
			   unsigned char *derBin,
			   uint32_t derBinLen)
{
    uint32_t 		rc = 0;
    X509 		*x509 = NULL;;
    unsigned char 	*tmpPtr;	/* because d2i_X509 moves the ptr */

    /* convert DER to X509 */
    if (rc == 0) {
	tmpPtr = derBin;
	x509 = d2i_X509(NULL, (const unsigned char **)&tmpPtr, derBinLen);
	if (x509 == NULL) {
	    printf("ERROR: convertX509DerToPem failed\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* convert X509 to PEM */
    if (rc == 0) {
	rc = convertX509ToPemMem(pemString,	/* freed by caller */
				 x509);
    }
    if (x509 != NULL) {
	X509_free(x509);
    }
    return rc;
}

/* aesencrypt() uses encryptionKey to encrypt decData to encData.  PKCS padding is used */

uint32_t aesencrypt(uint8_t **encData,		/* freed by caller */
		    uint32_t *encDataLen,
		    uint8_t *decData,
		    uint32_t decDataLen,
		    TPM2B_DIGEST *encryptionKey)
{
    uint32_t 	rc = 0;
    int		irc = 0;

    /* construct the encryption key */
    AES_KEY aesEncKey;
    if (rc == 0) {
	irc = AES_set_encrypt_key(encryptionKey->t.buffer, 256, &aesEncKey);
	if (irc != 0) {
	    printf("ERROR: aesencrypt: AES_set_encrypt_key failed\n");
            rc = ASE_OSSL_AES;      /* should never occur, null pointers or bad bit size */
        }
    }
    /* allocate memory for the encrypted data */
    uint32_t		padLength;
    if (rc == 0) {
	if (vverbose) printf("aesencrypt: input length %u\n", decDataLen);
        /* calculate the pad length and padded data length */
        padLength = TPM_AES_BLOCK_SIZE - (decDataLen % TPM_AES_BLOCK_SIZE);
        *encDataLen = decDataLen + padLength;
        if (vverbose) printf("aesencrypt: padded length %u pad length %u\n",
			     *encDataLen, padLength);
        /* allocate memory for the encrypted response */
        *encData = malloc(*encDataLen);		/* freed by caller */
	if (*encData == NULL) {
	    printf("ERROR: aesencrypt: could not malloc %u bytes\n",
		   *encDataLen);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    unsigned char       *decDataPadded = NULL;
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        decDataPadded = malloc(*encDataLen);	/* freed @1 */
	if (decDataPadded == NULL) {
	    printf("ERROR: aesencrypt: could not malloc %u bytes\n",
		   *encDataLen);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decDataPadded, decData, decDataLen);
	/* pad the decrypted clear text data */
        /* last gets pad = pad length */
        memset(decDataPadded + decDataLen, padLength, padLength);
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
        /* encrypt the padded input to the output */
        AES_cbc_encrypt(decDataPadded,
                        *encData,
                        *encDataLen,
                        &aesEncKey,
                        ivec,
                        AES_ENCRYPT);
    }
    free(decDataPadded);     /* @1 */
    return rc;
}

/* aesdecrypt() uses encryptionKey to decrypt encData to decData.  PKCS padding is checked */

uint32_t aesdecrypt(unsigned char **decData,   		/* output decrypted data, caller frees */
		    uint32_t *decDataLen,		/* output */
		    const unsigned char *encData,	/* input encrypted data */
		    uint32_t encDataLen,		/* input */
		    TPM2B_DIGEST *decryptionKey)	/* input AES key */
{
    uint32_t 		rc = 0;
    int			irc = 0;
    uint32_t		i;
    uint32_t		padLength;
    unsigned char       *padData;

    if (vverbose) printf("aesdecrypt: Length %u\n", encDataLen);
    /* sanity check encrypted length */
    if (rc == 0) {
	if (encDataLen < TPM_AES_BLOCK_SIZE) {
	    printf("ERROR: aesdecrypt: bad encrypted length %u\n", encDataLen);
	    rc = ACE_OSSL_AES;
	}
    }
    /* construct the decryption key */
    AES_KEY aesEncKey;
    if (rc == 0) {
	irc = AES_set_decrypt_key(decryptionKey->t.buffer, 256, &aesEncKey);
	if (irc != 0) {
	    printf("ERROR: aesencrypt: AES_set_encrypt_key failed\n");
            rc = ASE_OSSL_AES;      /* should never occur, null pointers or bad bit size */
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
	*decData = malloc(encDataLen);		/* freed by caller */
	if (*decData == NULL) {
	    printf("ERROR: aesencrypt: could not malloc %u bytes\n",
		   encDataLen);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* decrypt the input to the padded output */
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    if (rc == 0) {
	/* set the IV */
	memset(ivec, 0, sizeof(ivec));
	/* decrypt the padded input to the output */
	AES_cbc_encrypt(encData,
			*decData,
			encDataLen,
			&aesEncKey,
			ivec,
			AES_DECRYPT);
    }
    /* get the pad length */
    if (rc == 0) {
	/* get the pad length from the last byte */
	padLength = (uint32_t)*(*decData + encDataLen - 1);
	/* sanity check the pad length */
	if (vverbose) printf("aesdecrypt: Pad length %u\n", padLength);
	if ((padLength == 0) ||
	    (padLength > TPM_AES_BLOCK_SIZE)) {
	    printf("ERROR: aesdecrypt: illegal pad length %u\n", padLength);
	    rc = ACE_OSSL_AES;
	}
    }
    if (rc == 0) {
	/* get the unpadded length */
	*decDataLen = encDataLen - padLength;
	/* pad starting point */
	padData = *decData + *decDataLen;
	/* sanity check the pad */
	for (i = 0 ; i < padLength ; i++, padData++) {
	    if (*padData != padLength) {
		if (vverbose) printf("aesdecrypt: Error, bad pad %02x at index %u\n",
		       *padData, i);
		rc = ACE_OSSL_AES;
	    }
	}
    }
    return rc;
}

/* getEcCurve() gets the TCG algorithm ID curve associated with the openssl EC_KEY.  Gets the length
   of the private key (in bytes).

   NOTE: OpenSSL 3.x specific, taken from cryptoutils.c
*/


TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
		  int 		*privateKeyBytes,
		  const EVP_PKEY *ecKey)
{
    TPM_RC  	rc = 0;
    int		irc;
    char 	curveName[64];

    if (rc == 0) {
	irc = EVP_PKEY_get_utf8_string_param(ecKey, OSSL_PKEY_PARAM_GROUP_NAME,
					     curveName, sizeof(curveName), NULL);
	if (irc != 1) {
	    printf("getEcCurve: Error getting curve\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* FIXME make table */
    if (rc == 0) {
	if (strcmp(curveName, "prime256v1") == 0) {
	    *curveID = TPM_ECC_NIST_P256;
	    *privateKeyBytes = 32;
	}
	else if (strcmp(curveName, "secp384r1") == 0) {
	    *curveID = TPM_ECC_NIST_P384;
	    *privateKeyBytes = 48;
	}
	else {
	    printf("getEcCurve: Error, curve %s not supported \n", curveName);
	    rc = TSS_RC_EC_KEY_CONVERT;

	}
    }
    return rc;
}

