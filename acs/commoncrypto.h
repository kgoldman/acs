/********************************************************************************/
/*										*/
/*		 	TPM 2.0 Attestation - Common Crypto	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2024					*/
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

#ifndef COMMONCRYPTO_H
#define COMMONCRYPTO_H

#include <stdio.h>
#include <stdint.h>

#define TPM_AES_BLOCK_SIZE 16

TPM_RC convertX509DerToPem(char **pemString,
			   unsigned char *derBin,
			   uint32_t derBinLen);
uint32_t convertX509ToString(char **x509String,
			     X509 *x509);
uint32_t convertX509ToEc(EC_KEY **ecKey,
			 X509 *x509);

TPM_RC createX509Name(X509_NAME **x509Name,
		      size_t entriesSize,
		      char **entries);

uint32_t aesencrypt(uint8_t **encData,
		    uint32_t *encDataLen,
		    uint8_t *decData,
		    uint32_t decDataLen,
		    TPM2B_DIGEST *encryptionKey);
uint32_t aesdecrypt(unsigned char **decData,
		    uint32_t *decDataLen,
		    const unsigned char *encData,
		    uint32_t encDataLen,
		    TPM2B_DIGEST *decryptionKey);

TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
		  int 		*privateKeyBytes,
		  const EVP_PKEY *ecKey);

#endif
