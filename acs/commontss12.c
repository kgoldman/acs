/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common TSS Functions	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commontss12.c 1183 2018-04-27 16:58:25Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017.					*/
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

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssprint.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include "ekutils.h"

#include "config.h"
#include "commontss12.h"

extern int verbose;
extern int vverbose;

TPM_RC getTpmVendor12(TSS_CONTEXT *tssContext,
		      char 	*tpmVendor)		/* 5 byte array */
{
    TPM_RC 			rc = 0;
    GetCapability12_In		in;
    GetCapability12_Out		out;
    
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = in.subCap;
	uint32_t scap32 = TPM_CAP_PROP_MANUFACTURER;

	in.capArea = TPM_CAP_PROPERTY;
	in.subCapSize = sizeof(uint32_t);;
	TSS_UINT32_Marshal(&scap32, &written, &buffer, NULL);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	memcpy(tpmVendor, out.resp, sizeof(uint32_t));
	tpmVendor[4] = '\0';
	if (vverbose) printf("INFO: getTpmVendor: %s\n", tpmVendor);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: getTpmVendor12: TPM_ORD_GetCapability failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

TPM_RC startOIAP(TSS_CONTEXT *tssContext,
		 TPM_AUTHHANDLE *sessionHandle)
{
    TPM_RC 			rc = 0;
    OIAP_Out 			out;
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 NULL,
			 NULL,
			 TPM_ORD_OIAP,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (verbose) printf("startOIAP: Handle %08x\n", out.authHandle);
	*sessionHandle = out.authHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("startOIAP: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* startOSAP() starts an OSAP session.  The password is used to establish the session shared secret.
   It returns the session handle.

*/

TPM_RC startOSAP(TSS_CONTEXT *tssContext,
		 TPM_AUTHHANDLE *sessionHandle,
		 UINT32 entityValue,		/* handle - owner, SRK, key */
		 const char *password)
{
    TPM_RC 			rc = 0;
    OSAP_In 			in ;
    OSAP_Out 			out;
    OSAP_Extra			extra;

    if (rc == 0) {
	in.entityValue = entityValue;
	if (in.entityValue == TPM_RH_SRK) {	/* SRK */
	    in.entityType = 0x0004;		/* XOR */
	}
	else if (in.entityValue == TPM_RH_OWNER) { /* owner */
	    in.entityType = 0x0002;		/* XOR */
	}
	else {					/* key */
	    in.entityType = 0x0005;		/* XOR */
	}
	extra.usagePassword = password;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 (EXTRA_PARAMETERS *)&extra,
			 TPM_ORD_OSAP,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (verbose) printf("startOSAP: Handle %08x\n", out.authHandle);
	*sessionHandle = out.authHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("startOSAP: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* flushSpecific() flushes the resource at the specified handle.

 */

TPM_RC flushSpecific(TSS_CONTEXT *tssContext,
		     TPM_HANDLE handle,
		     TPM_RESOURCE_TYPE resourceType)
{
    TPM_RC			rc = 0;
    FlushSpecific_In 		in;

    if (vverbose) printf("flushSpecific: Entry, handle %08x\n", handle);
    if (rc == 0) {
	in.handle = handle;
	in.resourceType = resourceType;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_FlushSpecific,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("flushSpecific: TPM2_FlushContext success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: flushSpecific: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* ownerReadInternalPub() reads either the EK or SRK, and returns the TPM_PUBKEY

 */

TPM_RC ownerReadInternalPub(TSS_CONTEXT *tssContext,
			    TPM_PUBKEY *ekPub,
			    TPM_KEY_HANDLE keyHandle,
			    TPM_AUTHHANDLE sessionHandle,
			    const char *ownerPassword)
{
    TPM_RC 			rc = 0;
    OwnerReadInternalPub_In	in;
    OwnerReadInternalPub_Out	out;

    if (rc == 0) {
	in.keyHandle = keyHandle;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_OwnerReadInternalPub,
			 sessionHandle, ownerPassword, 1,
			 TPM_RH_NULL, NULL, 0);
	
    }
    if (rc == 0) {
	*ekPub = out.publicPortion;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ownerReadInternalPub: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* createAttestationKey12() makes the attestation identity key under the SRK parent.

   The key is not loaded.  The public and private parts are written to files.

   Returns the marshaled attestation signing key TPMT_PUBLIC.
*/

TPM_RC createAttestationKey12(TSS_CONTEXT *tssContext,
			      TPM_KEY12 *attestKey,
			      TPM_AUTHHANDLE sessionHandle0,	/* SRK OIAP session */
			      const char *srkPassword,
			      const char *ownerPassword)
{
    TPM_RC 			rc = 0;
    MakeIdentity_In		in;
    MakeIdentity_Out		out;
    TPM_AUTHHANDLE 		sessionHandle1;			/* owner OSAP session */
    if (rc == 0) {
	rc = startOSAP(tssContext, &sessionHandle1, TPM_RH_OWNER, ownerPassword);
    }
    if (rc == 0) {
	memset(in.identityAuth, 0, SHA1_DIGEST_SIZE);
	memset(in.labelPrivCADigest, 0, SHA1_DIGEST_SIZE);
	in.idKeyParams.tag = TPM_TAG_KEY12;
	in.idKeyParams.fill = 0;
	in.idKeyParams.keyUsage = TPM_KEY_IDENTITY; 
	in.idKeyParams.keyFlags = 0;
	in.idKeyParams.authDataUsage = TPM_AUTH_NEVER;
	in.idKeyParams.algorithmParms.algorithmID = TPM_ALG_RSA;  
	in.idKeyParams.algorithmParms.encScheme = TPM_ES_NONE;  
	in.idKeyParams.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;  
	in.idKeyParams.algorithmParms.parms.rsaParms.keyLength = 2048;  
	in.idKeyParams.algorithmParms.parms.rsaParms.numPrimes = 2;  
	in.idKeyParams.algorithmParms.parms.rsaParms.exponentSize = 0;  
	in.idKeyParams.PCRInfo.tag = TPM_TAG_PCR_INFO_LONG;
	in.idKeyParams.PCRInfo.localityAtCreation = TPM_LOC_ZERO;
	in.idKeyParams.PCRInfo.localityAtRelease = TPM_LOC_ALL;
	in.idKeyParams.PCRInfo.creationPCRSelection.sizeOfSelect = 3;
	memset(in.idKeyParams.PCRInfo.creationPCRSelection.pcrSelect, 0, 3);
	in.idKeyParams.PCRInfo.releasePCRSelection.sizeOfSelect = 3;
	memset(in.idKeyParams.PCRInfo.releasePCRSelection.pcrSelect, 0, 3);
	memset(in.idKeyParams.PCRInfo.digestAtCreation, 0, SHA1_DIGEST_SIZE);
	memset(in.idKeyParams.PCRInfo.digestAtRelease, 0, SHA1_DIGEST_SIZE);
	in.idKeyParams.pubKey.keyLength = 0;   
	in.idKeyParams.encData.keyLength = 0;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_MakeIdentity,
			 sessionHandle0, srkPassword, 1,
			 sessionHandle1, ownerPassword, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    /* return the attestation key structures */
    if (rc == 0) {
	*attestKey = out.idKey;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: createAttestationKey12: TPM_MakeIdentity failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}


/* loadObject12() loads the key under the SRK

   Returns the loaded key handle.
*/

TPM_RC loadObject12(TSS_CONTEXT *tssContext,
		    TPM_HANDLE 	*handle,
		    TPM_KEY12 	*attestKey,
		    TPM_AUTHHANDLE sessionHandle0,	/* OIAP session */
		    const char 	*parentPassword)
{
    TPM_RC			rc = 0;
    LoadKey2_In			in;
    LoadKey2_Out		out;

    if (rc == 0) {
	in.parentHandle = TPM_RH_SRK;
	in.inKey = *attestKey;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_LoadKey2,
			 sessionHandle0, parentPassword, 1,
			 TPM_RH_NULL, NULL, 0);
	
    }
    if (rc == 0) {
	if (vverbose) printf("loadObject12: Handle %08x\n", out.inkeyHandle);
	*handle = out.inkeyHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: loadObject12: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* readPcrs12() reads all the TPM PCRs.  It reads one PCR at a time.

   It reads the banks specified by pcrSelection, but ignores the bit mask and reads all PCRs.
*/

uint32_t readPcrs12(TSS_CONTEXT *tssContext,
		    TPML_PCR12_BANK *pcrBank,
		    const TPM_PCR_SELECTION *pcrSelection)
{
    TPM_RC		rc = 0;
    PcrRead12_In	in;
    PcrRead12_Out	out;
    uint32_t		pcrIndex;		/* iterate through PCRs */

    pcrSelection = pcrSelection;
    /* iterate through each select byte */
    for (pcrIndex = 0 ; (rc == 0) && (pcrIndex < IMPLEMENTATION_PCR) ; pcrIndex ++) {
	/* call TSS to execute the command */
	if (rc == 0) {
	    in.pcrIndex = pcrIndex;
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out, 
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_ORD_PcrRead,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    pcrBank->count++; 
	    /* copy the PCR value to pcrBank->pcrBank[bank].digests[pcrNum].t. */
	    memcpy(pcrBank->digests[pcrIndex], out.outDigest, SHA1_DIGEST_SIZE);
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: readPcrs12: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

/* signQuote() signs a quote using the attestation keyHandle.  It assumes that nonceBin is
   TPM_NONCE_SIZE.

   It returns the quote data and signature.

*/

uint32_t signQuote12(TSS_CONTEXT *tssContext,
		     TPM_PCR_INFO_SHORT *pcrData,
		     uint32_t *versionInfoSize,
		     TPM_CAP_VERSION_INFO *versionInfo,
		     uint32_t *signatureSize,
		     uint8_t *signature,
		     TPM_HANDLE keyHandle,	/* attestation key */
		     const unsigned char *nonceBin,
		     const TPM_PCR_SELECTION *pcrSelection,
		     TPM_AUTHHANDLE sessionHandle0,	/* OIAP session */
		     const char *keyPassword)
{
    TPM_RC			rc = 0;
    Quote2_In			in;
    Quote2_Out			out;
    
    if (rc == 0) {
	in.keyHandle = keyHandle;
	memcpy(in.externalData, nonceBin, TPM_NONCE_SIZE);
	in.targetPCR = *pcrSelection;
	in.addVersion = 1;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_ORD_Quote2,
			 sessionHandle0, keyPassword, 1,
			 TPM_RH_NULL, NULL, 0);
 	if (rc != 0) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: quote2: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    /* return quote2 results */
    if (rc == 0) {
	*pcrData = out.pcrData;
	*versionInfoSize = out.versionInfoSize;
	*versionInfo = out.versionInfo;
	*signatureSize = out.sigSize;
	memcpy(signature, out.sig, out.sigSize);
    }
    return rc;
}

