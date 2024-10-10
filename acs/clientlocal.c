/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client Side Local Functions		*/
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

/* This is the version that uses the local TPM.

   The overall steps are:

    Create an attestation key.
    Send the attestation key and EK certificate to the server
    Activate credential on the attestation key certificate
    Send the attestation key certificate back to the server.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include "ekutils.h"
#include "imalib.h"

#include "clientlocal.h"

#include "config.h"
#include "commontss.h"

extern int verbose;
extern int vverbose;

/* local function prototypes */

/* createEnrollmentData()

   creates an SRK primary key and makes it persistent if it does not already
   exist.

   creates an attestation key under that primary key.

   reads the EK certificate

   /// Create enrollment data
   /// @param[out] tpmVendor Input is a minimum 5 char array, output is NUL terminated TPM Vendor
   /// @param[out] ekCertLength Byte length of ekCertificate
   /// @param[out] ekCertificate marshaled EK Certificate, buffer must be freed by caller
   /// @param[out] attestPriv Attestation private key
   /// @param[out] attestPub Attestation public key
   /// @param[out] attestPubLength Byte length of attestPubBin
   /// @param[out] attestPubBin Buffer containing marshalled TPMT_PUBLIC attestation public key,
   buffer must be freed by caller
   /// @param[in] nvIndex TPM Index of the EK certificate
*/

TPM_RC createEnrollmentData(char *tpmVendor,			/* freed by caller */
			    uint16_t *ekCertLength,
			    unsigned char **ekCertificate,	/* freed by caller */
			    TPM2B_PRIVATE *attestPriv,
			    TPM2B_PUBLIC *attestPub,
			    uint16_t *attestPubLength,
			    unsigned char **attestPubBin,	/* freed by caller */
			    TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 		rc = 0;
    TSS_CONTEXT 	*tssContext = NULL;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* get the TPM vendor */
    if (rc == 0) {
	rc = getTpmVendor(tssContext, tpmVendor);	/* freed by caller */
    }
    /* does the SRK already exist */
    int exists;		/* flag, true if SRK exists */
    if (rc == 0) {
	rc = getCapSrk(tssContext, &exists);
    }
    /* create the primary SRK if it does not exist */
    TPM_HANDLE 	srkHandle;	/* the loaded SRK transient handle */
    if ((rc == 0) && !exists) {
	rc = createSrk(tssContext, &srkHandle);
    }
    /* make the SRK persistent in the TPM */
    if ((rc == 0) && !exists) {
	rc = persistSrk(tssContext, srkHandle);
    }
    /* flush the transient copy of the SRK */
    if ((rc == 0) && !exists) {
	rc = flushContext(tssContext, srkHandle);
    }
    /* Create the attestation signing key under the primary key */
    if (rc == 0) {
	rc = createAttestationKey(tssContext,
				  nvIndex,				/* RSA or EC */
				  attestPriv, attestPub,
				  attestPubLength, attestPubBin);	/* freed by caller */
    }
    /* read the TPM EK certificate from TPM NV */
    if (rc == 0) {
	rc = getIndexContents(tssContext,
			      ekCertificate,		/* freed by caller */
			      ekCertLength,		/* total size read */
			      nvIndex);			/* RSA or EC */
	if (rc != 0) {
	    if (verbose) printf("ERROR: createEnrollmentData: EK certificate not found at %08x\n",
				nvIndex);
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	tssContext = NULL;
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

/* getIntermediateCertificate()

   reads the EK intermadiate CA certificates

   /// reads the EK intermadiate CA certificates
   /// @param[out] intermediateCertLength Byte length of Certificate
   /// @param[out] intermediateCert marshaled Certificate, buffer must be freed by caller
*/

TPM_RC getIntermediateCertificate(uint16_t *intermediateCertLength,
				  unsigned char **intermediateCert)	/* freed by caller */
{
    TPM_RC 		rc = 0;
    int 		done = FALSE;
    TPMI_RH_NV_INDEX 	nvIndex;
    TSS_CONTEXT 	*tssContext = NULL;
    uint16_t 		tmpLength = 0;
    unsigned char 	*tmpBuffer = NULL;

    /* typically there are no intermediate certificates */
    *intermediateCertLength = 0;
    *intermediateCert = NULL;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    for (nvIndex = INTERMEDIATE_CERT_INDEX_FIRST ;
	 (rc == 0) && (nvIndex < INTERMEDIATE_CERT_INDEX_LAST) && !done ; nvIndex++) {

	if (vverbose) printf("getIntermediateCertificate: reading %08x\n", nvIndex);
	rc = getIndexContents(tssContext,
			      &tmpBuffer ,		/* freed @1 */
			      &tmpLength,		/* total size read */
			      nvIndex);
	/* keep reading until the NV index is not defined */
	/* 0x3f is rc, 80 is FMT_1 */
	if ((rc & 0x00bf) == TPM_RC_HANDLE) {
	    done = TRUE;
	    rc = 0;		/* not found is not an error */
	    if (vverbose) printf("getIntermediateCertificate: not found at %08x\n",
				 nvIndex);
	}
	else if (rc != 0) {
	    if (verbose) printf("ERROR: getIntermediateCertificate: reading %08x\n",
				nvIndex);
	}
	/* append the certificate to the buffer */
	else {
	    if (vverbose) printf("getIntermediateCertificate: read %hu bytes\n", tmpLength);
	    if (rc == 0) {
		rc = TSS_Realloc(intermediateCert, *intermediateCertLength + tmpLength);
	    }
	    if (rc == 0) {
		memcpy(*intermediateCert + *intermediateCertLength, tmpBuffer, tmpLength);
		*intermediateCertLength += tmpLength;
		free(tmpBuffer);		/* @1 */
		tmpBuffer = NULL;
	    }
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	tssContext = NULL;
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

/* recoverAttestationKeyCertificate() recreates the primary EK, loads the attestation key pair, and
   then runs activate credential to recover the secret from the credential blob.

   Returns the recovered symmetric key.

   /// Recover attestation key certificate
   /// @param[out] certInfo Recovered symmetric key
   /// @param[in] attestPriv Attestation private key
   /// @param[in] attestPub Attestation public key
   /// @param[in] credentialBlobBin Credential blob from server MakeCredential
   /// @param[in] credentialBlobBinSize Byte size of credentialBlobBin
   /// @param[in] secretBin Secret from server MakeCredential
   /// @param[in] secretBinSize Byte size of secretBin
*/

TPM_RC recoverAttestationKeyCertificate(TPM2B_DIGEST 	*certInfo,
					TPM2B_PRIVATE 	*attestPriv,
					TPM2B_PUBLIC 	*attestPub,
					TPMI_RH_NV_INDEX ekCertIndex,
					unsigned char 	*credentialBlobBin,
					size_t 		credentialBlobBinSize,
					unsigned char 	*secretBin,
					size_t 		secretBinSize)
{
    TPM_RC 	rc = 0;
    TPM_RC 	rc1;
    /*
      Create the EK primary key
    */
    TSS_CONTEXT 	*tssContext = NULL;
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* get the EK nonce, if it exists */
    unsigned char 	*nonce = NULL;
    uint16_t 		nonceSize = 0;
    TPMI_RH_NV_INDEX 	ekNonceIndex = 0;
    TPMI_RH_NV_INDEX 	ekTemplateIndex = 0;
    TPMI_ALG_HASH  	sessionHashAlg;
    if (rc == 0) {
	switch (ekCertIndex) {
	  case EK_CERT_RSA_INDEX:
	    ekNonceIndex = EK_NONCE_RSA_INDEX;
	    ekTemplateIndex = EK_TEMPLATE_RSA_INDEX;
	    sessionHashAlg = TPM_ALG_SHA256;
	    break;
	  case EK_CERT_EC_INDEX:
	    ekNonceIndex = EK_NONCE_EC_INDEX;
	    ekTemplateIndex = EK_TEMPLATE_EC_INDEX;
	    sessionHashAlg = TPM_ALG_SHA256;
	    break;
	  case EK_CERT_RSA_3072_INDEX_H6:
	    ekNonceIndex = 0;
	    ekTemplateIndex = 0;
	    sessionHashAlg = TPM_ALG_SHA384;
	    break;
	  case EK_CERT_ECC_NISTP384_INDEX_H3:
	    ekNonceIndex = 0;
	    ekTemplateIndex = 0;
	    sessionHashAlg = TPM_ALG_SHA384;
	    break;
	  default:
	    if (verbose) printf("ERROR: recoverAttestationKeyCertificate algorithm not supported\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if ((rc == 0) && (ekNonceIndex != 0)) {
	rc = processEKNonce(tssContext, &nonce, &nonceSize, /* freed @6 */
			    ekNonceIndex, vverbose);
	if ((rc & 0x00bf) == TPM_RC_HANDLE) {
	    if (verbose) printf("INFO: recoverAttestationKeyCertificate: "
				"EK nonce not found, use default template\n");
	    rc = 0;
	}
    }
    TPMT_PUBLIC 	tpmtPublicIn;		/* template */
    TPMT_PUBLIC 	tpmtPublicOut;		/* primary key */
    if ((rc == 0) && (ekTemplateIndex != 0)) {
	/* if the nonce was found, get the EK template.  */
	if (nonce != NULL) {
	    rc = processEKTemplate(tssContext, &tpmtPublicIn, ekTemplateIndex, vverbose);
	}
    }
    TPM_HANDLE		ekKeyHandle = 0;
    /* create the primary key.  nonce NULL indicates that the default IWG template should be
       used.  */
    if (rc == 0) {
	rc = processCreatePrimary(tssContext,
				  &ekKeyHandle,		/* loaded EK handle, flushed @8 */
				  ekCertIndex,		/* RSA or EC algorithm */
				  nonce, nonceSize,	/* EK nonce, can be NULL */
				  &tpmtPublicIn,	/* template */
				  &tpmtPublicOut,	/* primary key */
				  TRUE,			/* noFlush */
				  vverbose);		/* print errors */
    }
    if (rc == 0) {
	if (verbose) printf("INFO: recoverAttestationKeyCertificate: EK Primary key Handle %08x\n",
			    ekKeyHandle);
    }
    /* load the attestation key saved in a file in the previous protocol step */
    TPMI_DH_OBJECT activateHandle = 0;
    if (rc == 0) {
	rc = loadObject(tssContext,		/* flushed @7 */
			&activateHandle,	/* loaded attestation key handle */
			attestPriv,
			attestPub);
    }
    if (rc == 0) {
	if (verbose) printf("INFO: recoverAttestationKeyCertificate: Attestation key %08x\n",
			    activateHandle);
    }
    /* activatecredential, recover the symmetric key generated by the server and used to encrypt the
       attestation certificate */
    if (rc == 0) {
	rc = activatecredential(tssContext,
				certInfo,		/* the symmetric key */
				activateHandle,
				ekKeyHandle,
				ekCertIndex,
				sessionHashAlg,
				credentialBlobBin,
				credentialBlobBinSize,
				secretBin,
				secretBinSize);
    }
    /* flush the attestation key */
    if (activateHandle != 0) {
	if (verbose) printf("INFO: recoverAttestationKeyCertificate: Flush attestation key %08x\n",
			    activateHandle);
	rc1 = flushContext(tssContext, activateHandle);	/* @7 */
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* flush the primary key */
    if (ekKeyHandle != 0) {
	if (verbose) printf("INFO: recoverAttestationKeyCertificate: Flush EK %08x\n",
			    ekKeyHandle);
	rc1 = flushContext(tssContext, ekKeyHandle);	/* @8 */
	if (rc == 0) {
	    rc = rc1;
	}
    }
    {
	rc1 = TSS_Delete(tssContext);
	tssContext = NULL;
	if (rc == 0) {
	    rc = rc1;
	}
    }
    free(nonce);		/* @6 */
    return rc;
}

/* runQuote() runs the TPM quote.  Loads a key whose public and private parts are at AK_PUB_FILENAME
   and AK_PRIV_FILENAME, under the parent at SRK_HANDLE.

   Returns the signature andquote data.

   The attestation key comes from files saved during enrollment.

   /// Retrieve TPM quote
   /// @param[out] quoted Quote from TPM
   /// @param[out] signature Quote signature from TPM
   /// @param[in] nonceBin Nonce supplied by server
   /// @param[in] nonceLen Byte length of nonceBin
   /// @param[in] pcrSelection PCRs to retrieve
   /// @param[in] attestPriv Attestation private key
   /// @param[in] attestPub Attestation public key
*/

TPM_RC runQuote(TPM2B_ATTEST *quoted,
		TPMT_SIGNATURE *signature,
		const unsigned char *nonceBin,
		size_t nonceLen,
		const TPML_PCR_SELECTION *pcrSelection,
		TPM2B_PRIVATE *attestPriv,	/* quote signing key */
		TPM2B_PUBLIC *attestPub)
{
    uint32_t 		rc = 0;
    TPM_RC 		rc1;
    TSS_CONTEXT		*tssContext = NULL;
    TPM_HANDLE 		keyHandle = 0;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* load the quote signing key */
    if (rc == 0) {
	if (vverbose) printf("runQuote: load attestation quote signing key\n");
	rc = loadObject(tssContext, &keyHandle, attestPriv, attestPub);
    }
    /* sign the quote */
    if (rc == 0) {
	TPMI_ALG_PUBLIC type = attestPub->publicArea.type;
	if (vverbose) printf("runQuote: sign quote with key handle %08x\n", keyHandle);
	rc = signQuote(tssContext,
		       quoted,
		       signature,
		       keyHandle,
		       type,
		       nonceBin, nonceLen,
		       pcrSelection);
    }
    /* flush the quote signing key */
    if ((tssContext != NULL) && (keyHandle != 0)) {
	rc1 = flushContext(tssContext,
			   keyHandle);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

/* runAudit() runs the TPM PCR read audit.  Loads a key whose public and private parts are at
   AK_PUB_FILENAME and AK_PRIV_FILENAME, under the parent at SRK_HANDLE.

   Returns the signature, audit data, and PCRs.

   The attestation key comes from files saved during enrollment.

   /// Retrieve TPM quote
   /// @param[out] pcrBanks PCR values
   /// @param[out] auditInfo from TPM
   /// @param[out] signature Quote signature from TPM
   /// @param[out] boottimeString Boot time as a string
   /// @param[in] boottimeStringLen Maximum byte length of boottimeString
   /// @param[in] nonceBin Nonce supplied by server
   /// @param[in] nonceLen Byte length of nonceBin
   /// @param[in] pcrSelection PCRs to retrieve
   /// @param[in] attestPriv Attestation private key
   /// @param[in] attestPub Attestation public key
   */

TPM_RC runAudit(TPML_PCR_BANKS *pcrBanks,
		TPM2B_ATTEST *auditInfo,
		TPMT_SIGNATURE *signature,
		char *boottimeString,
		size_t boottimeStringLen,
		const unsigned char *nonceBin,
		size_t nonceLen,
		const TPML_PCR_SELECTION *pcrSelection,
		TPM2B_PRIVATE *attestPriv,	/* signing key */
		TPM2B_PUBLIC *attestPub)
{
    uint32_t 			rc = 0;
    TPM_RC 			rc1;
    TSS_CONTEXT			*tssContext = NULL;
    TPM_HANDLE 			keyHandle = 0;
    TPMI_SH_AUTH_SESSION 	sessionHandle = 0;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* load the quote signing key */
    if (rc == 0) {
	if (vverbose) printf("runAudit: load attestation quote signing key\n");
	rc = loadObject(tssContext, &keyHandle, attestPriv, attestPub);
    }
    /* start the audit session */
    if (rc == 0) {
	rc = makeHmacSession(tssContext, &sessionHandle);
    }
    /* read the PCRs for all banks - in an audit session */
    if (rc == 0) {
	if (vverbose) printf("runAudit: read PCRs in audit session %08x\n", sessionHandle);
	rc = readPcrsA(tssContext,
		       pcrBanks,		/* TPML_PCR_BANKS, PCR and counter */
		       sessionHandle,
		       pcrSelection);
    }
    /* get the signed audit digest */
    if (rc == 0) {
	TPMI_ALG_PUBLIC type = attestPub->publicArea.type;
	if (vverbose) printf("runAudit: sign with key handle %08x\n", keyHandle);
	rc = getAuditDigest(tssContext,
			    auditInfo,
			    signature,
			    keyHandle,
			    type,
			    sessionHandle,
			    nonceBin, nonceLen);
    }
    /* flush the quote signing key */
    if ((tssContext != NULL) && (keyHandle != 0)) {
	rc1 = flushContext(tssContext,
			   keyHandle);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* flush the session */
    if ((tssContext != NULL) && (sessionHandle != 0)) {
	rc1 = flushContext(tssContext,
			   sessionHandle);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* return the boot time for the quote command packet.  This is done at the 'local' layer because
       the upper layer may not have access to the clock. */
    if (rc == 0) {
	/* if the upper layer already determined the boot time, leave it unaltered */
	if (boottimeString[0] == '\0') {
	    rc = getBootTime(boottimeString, boottimeStringLen);
	}
    }
    return rc;
}

/* For the local interface, this is a no-op, since the event log is already in a file.

   For the hcall interface, this function must read the entire event log and store it in a file.

   The obvious other approach, to use a memory array, would be more efficient for hcalls, since it
   saves the file write and read.  It does not easily work for the local interface, because the log
   is a pseudo-file, so there is no way to fseek to the end to get the file size.

   /// Retrieve TPM Log
   /// @param[in] biosInputFilename Name of file to place binary logfile
*/

TPM_RC retrieveTPMLog(const char *biosInputFilename)
{
    biosInputFilename = biosInputFilename;
    return 0;
}

/* getBootTime() reads the machine boot time from /proc/stat

   The line in the file is of the form:  btime nnnnn

   where n is a decimal string.

   boottimeMax is the maximum size of the supplied boottime array.
*/

uint32_t getBootTime(char *boottime,
		     size_t boottimeMax)
{
    uint32_t rc = 0;
    FILE *fp = NULL;

    if (rc == 0) {
	fp = fopen("/proc/stat", "r");		/* closed @1 */
	if (fp == NULL) {
	    printf("ERROR: getBootTime: /proc/stat open failed\n");
	    rc = 1;
	}
    }
    char line [128];
    char *p = NULL;	/* for fgets, then moves */
    if (rc == 0) {
	do {
	    /* read a line from /proc/stat */
	    p = fgets(line, sizeof(line), fp);
	    if (p != NULL) {
		if (strncmp(line, "btime", strlen("btime")) == 0) {
		    if (vverbose) printf("getBootTime: %s", line);
		    break;	/* if found the btime line, exit loop */
		}
	    }
	} while (p != NULL);	/* if no more lines, exit loop */
	/* if the btime line was not found in /proc/stat, return an error */
	if (p == NULL) {
	    printf("ERROR: getBootTime: btime not found\n");
	    rc = 1;
	}
    }
    char *pdec = NULL;	/* point to boot time decimal string */
    /* should be space between btime and decimal string */
    if (rc == 0) {
	p = strchr(line, (int)' ');
	if (p == NULL) {
	    printf("ERROR: getBootTime: parse error\n");
	    rc = 1;
	}
	else {
	    pdec = p+1;	/* skip past the space */
	}
    }
    char *pend = NULL;	/* point to newline, changed to nul */
    if (rc == 0) {
	pend = strchr(pdec, (int)'\n');
	/* remove trailing newline from decimal boot time */
	if (pend != NULL) {
	    *pend = '\0';
	}
	if (vverbose) printf("getBootTime: boottime string %s\n", pdec);
	time_t bootTimeBin;
	sscanf(pdec, "%lu", (unsigned long *)&bootTimeBin);
	if (vverbose) printf("getBootTime: boottime long: %lu\n", (unsigned long)bootTimeBin);
	struct tm *bootTimeTm = localtime(&bootTimeBin);
	strftime(boottime, boottimeMax, "%Y-%m-%d %H:%M:%S", bootTimeTm);
	if (vverbose) printf("getBootTime: %s\n", boottime);
    }
    if (fp != NULL) {
	fclose(fp);		/* @1 */
    }
    return rc;
}
