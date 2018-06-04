/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client Side Local Functions		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientlocal.c 1159 2018-04-17 15:10:01Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017					*/
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

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssprint.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include "ekutils.h"
#include "imalib.h"

#include "clientlocal.h"

#include "config.h"
#include "commontss.h"

extern int verbose;
extern int vverbose;

/* local function prototypes */

static uint32_t getBootTime(char *boottime,
			    size_t boottimeMax);
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
    uint16_t 		nonceSize;
    TPMI_RH_NV_INDEX 	ekNonceIndex;
    TPMI_RH_NV_INDEX 	ekTemplateIndex;
    if (rc == 0) {
	if (ekCertIndex == EK_CERT_RSA_INDEX) {
	    ekNonceIndex = EK_NONCE_RSA_INDEX;
	    ekTemplateIndex = EK_TEMPLATE_RSA_INDEX;
	}
	else if (ekCertIndex == EK_CERT_EC_INDEX) {
	    ekNonceIndex = EK_NONCE_EC_INDEX;
	    ekTemplateIndex = EK_TEMPLATE_EC_INDEX;
	}
	else {
	    if (verbose) printf("ERROR: recoverAttestationKeyCertificate algoritm not supported\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = processEKNonce(tssContext, &nonce, &nonceSize, /* freed @6 */
			    ekNonceIndex, vverbose);
	if ((rc & 0xff) == TPM_RC_HANDLE) {
	    if (verbose) printf("INFO: recoverAttestationKeyCertificate: "
				"EK nonce not found, use default template\n");
	    rc = 0;
	}
    }
    TPMT_PUBLIC 	tpmtPublicIn;		/* template */
    TPMT_PUBLIC 	tpmtPublicOut;		/* primary key */
    if (rc == 0) {
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

   Returns the signature, quote data, and PCRs.

   The attestation key comes from files saved during enrollment.

   /// Retrieve TPM quote
   /// @param[out] pcrBanks PCR values
   /// @param[out] quoted Quote from TPM
   /// @param[out] signature Quote signature from TPM
   /// @param[out] boottimeString Boot time as a string
   /// @param[in] boottimeStringLen Maximum byte length of boottimeString 
   /// @param[in] nonceBin Nonce supplied by server
   /// @param[in] nonceLen Byte length of nonceBin
   /// @param[in] pcrSelection PCRs to retrieve
   /// @param[in] attestPriv Attestation private key
   /// @param[in] attestPub Attestation public key
*/

TPM_RC runQuote(TPML_PCR_BANKS *pcrBanks,
		TPM2B_ATTEST *quoted,
		TPMT_SIGNATURE *signature,
		char *boottimeString,
		size_t boottimeStringLen,
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
    int			pcr10Match = 0;
    TPML_PCR_BANKS 	pcrBanksCheck;
    
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
    while ((rc == 0) && !pcr10Match) {
	    
	/* read all the PCRs for each bank specified in pcrSelection.  It ignores the bit mask, just
	   for debug and demo displays. This affects performance slightly, but PCR read time is
	   negligible compared to the quote time.*/
	if (rc == 0) {
	    rc = readPcrs(tssContext,
			  pcrBanks,
			  pcrSelection);
	}
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
	/* Since read and quote are not atomic, read again and make sure PCR's have not changed.
	   This should not be an issue for BIOS, since BIOS is exited long before the first quote.
	   It could be for IMA, since extends can come between the read and quote. */
	if (rc == 0) {
	    rc = readPcrs(tssContext,
			  &pcrBanksCheck,
			  pcrSelection);
	}
	/* Currently, only PCR 10, the IMA PCR, is checked.  All PCRs are read because (1) the code
	   is already there, and (2) other PCRs may be of interest in the future. */

	uint32_t	bank;	/* iterate through PCR banks */
	int		irc;
	pcr10Match = 1;

	for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {
		
	    if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA256) {
		irc = memcmp(pcrBanks->pcrBank[bank].digests[IMA_PCR].t.buffer,
			     pcrBanksCheck.pcrBank[bank].digests[IMA_PCR].t.buffer,
			     SHA256_DIGEST_SIZE);
		if (irc != 0) {
		    if (vverbose) printf("runQuote: PCR %u SHA-256 bank mismatch, retry\n",
					 IMA_PCR);
		    pcr10Match = 0;
		}
		    
	    }
	    else if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA1) {
		irc = memcmp(pcrBanks->pcrBank[bank].digests[IMA_PCR].t.buffer,
			     pcrBanksCheck.pcrBank[bank].digests[IMA_PCR].t.buffer,
			     SHA1_DIGEST_SIZE);
		if (irc != 0) {
		    if (vverbose) printf("runQuote: PCR %u SHA-1 bank mismatch, retry\n",
					 IMA_PCR);
		    pcr10Match = 0;
		}
	    }
	    else {
		printf("ERROR: runQuote: does not support algorithm %04x yet\n",
		       pcrSelection->pcrSelections[bank].hash);
		rc = EXIT_FAILURE;
	    }
	}
	if ((rc == 0) && pcr10Match) {
	    if (vverbose) printf("runQuote: PCR matched before and after quote\n");
	}
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

