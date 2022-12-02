/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common TSS Functions	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commontss.c 1607 2020-04-28 21:35:05Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2020.					*/
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

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

#include "ekutils.h"

#include "config.h"
#include "commontss.h"

extern int verbose;
extern int vverbose;

TPM_RC getTpmVendor(TSS_CONTEXT *tssContext,
		    char 	*tpmVendor)		/* 5 byte array */
{
    TPM_RC 			rc = 0;
    GetCapability_In 		in;
    GetCapability_Out		out;
    
    if (rc == 0) {
	in.capability = TPM_CAP_TPM_PROPERTIES;
	in.property = TPM_PT_MANUFACTURER;
	in.propertyCount = 1;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	tpmVendor[0] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >> 24) & 0xff;
	tpmVendor[1] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >> 16) & 0xff;
	tpmVendor[2] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >>  8) & 0xff;
	tpmVendor[3] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >>  0) & 0xff;
	tpmVendor[4] = '\0';
	if (vverbose) printf("INFO: getTpmVendor: %s\n", tpmVendor);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: getTpmVendor: TPM2_GetCapability failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* getCapSrk() probes the TPM to determine if the SRK exists.

   Returns TRUE or FALSE.
*/

TPM_RC getCapSrk(TSS_CONTEXT 	*tssContext,
		 int   		*exists)
{
    TPM_RC 			rc = 0;
    GetCapability_In 		in;
    GetCapability_Out		out;

    if (rc == 0) {
	in.capability = TPM_CAP_HANDLES;
	in.property = TPM_HT_PERSISTENT << 24;
	in.propertyCount = 1;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	/* if the getcap returned the SRK handle */
	if ((out.capabilityData.data.handles.count > 0) &&
	    (out.capabilityData.data.handles.handle[0] == SRK_HANDLE)) {
	    *exists = TRUE;
	}
	else {
	    *exists = FALSE;
	}
	if (vverbose) printf("INFO: getCapSrk: TPM2_GetCapability exists %u\n",
			     *exists);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: getCapSrk: TPM2_GetCapability failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* createSrk() creates a storage primary key in the owner hierarchy, returning the loaded transient
   key handle

*/

TPM_RC createSrk(TSS_CONTEXT 	*tssContext,
		 TPM_HANDLE 	*handle)
{
    TPM_RC			rc = 0;
    CreatePrimary_In 		in;
    CreatePrimary_Out 		out;
    
    /* set up the createprimary in parameters */
    if (rc == 0) {
	in.primaryHandle = TPM_RH_OWNER;
	in.inSensitive.sensitive.userAuth.t.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;
	/* creation data */
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
	in.inPublic.publicArea.type = TPM_ALG_RSA;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.objectAttributes.val = TPMA_OBJECT_NODA |
							TPMA_OBJECT_FIXEDTPM |
							TPMA_OBJECT_FIXEDPARENT |
							TPMA_OBJECT_SENSITIVEDATAORIGIN |
							TPMA_OBJECT_USERWITHAUTH |
							TPMA_OBJECT_DECRYPT |
							TPMA_OBJECT_RESTRICTED;
	in.inPublic.publicArea.authPolicy.t.size = 0;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = 0;
	in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
	in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
	in.inPublic.publicArea.unique.rsa.t.size = 0;
	in.outsideInfo.t.size = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }	
    if (rc == 0) {
	if (vverbose) printf("createSrk: Handle %08x\n", out.objectHandle);
	*handle  = out.objectHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: createSrk: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}

/* persistSrk() makes a copy of the SRK in TPM non-volatile memory.  The transient copy is not
   flushed.

*/

TPM_RC persistSrk(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	srkHandle)
{
    TPM_RC			rc = 0;
    EvictControl_In 		in;

    if (rc == 0) {
	in.auth = TPM_RH_OWNER;
	in.objectHandle = srkHandle;
	in.persistentHandle = SRK_HANDLE;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_EvictControl,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    if (vverbose) printf("INFO: persistSrk: TPM2_EvictControl success\n");
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: evictcontrol: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

/* createAttestationKey() creates the attestation signing key under the SRK parent.

   The key is not loaded.  The public and private parts are written to files.

   Returns the marshaled attestation signing key TPMT_PUBLIC.
*/

TPM_RC createAttestationKey(TSS_CONTEXT *tssContext,
			    TPMI_RH_NV_INDEX nvIndex,
			    TPM2B_PRIVATE *attestPriv,
			    TPM2B_PUBLIC *attestPub,
			    uint16_t *attestPubLength,
			    unsigned char **attestPubBin)	/* freed by caller */	
{
    TPM_RC 			rc = 0;
    Create_In 			in;
    Create_Out 			out;

    /* create the attestation key */
    if (rc == 0) {
	in.parentHandle = SRK_HANDLE;			/* under the SRK */
	in.inSensitive.sensitive.userAuth.t.size = 0;	/* password*/
	in.inSensitive.sensitive.data.t.size = 0;	/* no sealed data */

	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	/* stClear is not set, so the attestation key context can be reloaded after a reboot */
	in.inPublic.publicArea.objectAttributes.val = TPMA_OBJECT_NODA |
						      TPMA_OBJECT_FIXEDTPM |
						      TPMA_OBJECT_FIXEDPARENT |
						      TPMA_OBJECT_SENSITIVEDATAORIGIN |
						      TPMA_OBJECT_USERWITHAUTH |
						      TPMA_OBJECT_SIGN |
						      TPMA_OBJECT_RESTRICTED;
	in.inPublic.publicArea.authPolicy.t.size = 0;
	if (nvIndex == EK_CERT_RSA_INDEX) {
	    in.inPublic.publicArea.type = TPM_ALG_RSA;
	    in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	    in.inPublic.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
		TPM_ALG_SHA256;
	    in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
	    in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
	    in.inPublic.publicArea.unique.rsa.t.size = 0;
	}
	else if (nvIndex == EK_CERT_EC_INDEX) {
	    in.inPublic.publicArea.type = TPM_ALG_ECC;
	    in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    in.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
		TPM_ALG_SHA256;
	    in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	    in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	    in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	    in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	    in.inPublic.publicArea.unique.ecc.y.t.size = 0;
	}
	else {
	    printf("ERROR: createAttestationKey unsupported algorithm\n");
	    rc = EXIT_FAILURE;
	}
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Create,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    if (vverbose) printf("INFO: createAttestationKey: TPM2_Create success\n");
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: createAttestationKey: TPM2_Create failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    /* return the attestation key public area */
    if (rc == 0) {
	rc = TSS_Structure_Marshal(attestPubBin,		/* freed by caller */
				   attestPubLength,
				   &out.outPublic.publicArea,
				   (MarshalFunction_t)TSS_TPMT_PUBLIC_Marshalu);
    }
    /* return the attestation key structures */
    if (rc == 0) {
	*attestPriv = out.outPrivate;
	*attestPub = out.outPublic;
    }
    return rc;
}

/* loadObject() loads the public and private parts under the parent handle

   Returns the loaded key handle.
*/

TPM_RC loadObject(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	*handle,
		  TPM2B_PRIVATE *attestPriv,
		  TPM2B_PUBLIC 	*attestPub)
{
    TPM_RC			rc = 0;
    Load_In 			in;
    Load_Out 			out;

    if (rc == 0) {
	in.parentHandle = SRK_HANDLE;
	in.inPrivate = *attestPriv;
	in.inPublic = *attestPub;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("loadObject: Handle %08x\n", out.objectHandle);
	*handle = out.objectHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: loadObject: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* activatecredential() runs the TPM2_ActivateCredential() using the client TPM.

 */

TPM_RC activatecredential(TSS_CONTEXT *tssContext,
			  TPM2B_DIGEST *certInfo,
			  TPM_HANDLE activateHandle,		/* loaded key */
			  TPM_HANDLE keyHandle,			/* loaded EK */
			  unsigned char *credentialBlobBin,	/* marshaled */
			  size_t credentialBlobBinSize,
			  unsigned char *secretBin,		/* marshaled */
			  size_t secretBinSize)
{
    TPM_RC			rc = 0;
    ActivateCredential_In 	in;
    ActivateCredential_Out 	out;
    uint8_t 			*tmpptr;
    uint32_t 			tmpsize;

    if (rc == 0) {
	in.activateHandle = activateHandle;
	in.keyHandle = keyHandle;
    }
    /* unmarshal the credential blob */
    if (rc == 0) {
	tmpptr = credentialBlobBin;
	tmpsize = credentialBlobBinSize;
	rc = TSS_TPM2B_ID_OBJECT_Unmarshalu(&in.credentialBlob, &tmpptr, &tmpsize);
    }
    /* unmarshal the secret */
    if (rc == 0) {
	tmpptr = secretBin;
	tmpsize = secretBinSize;
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&in.secret, &tmpptr, &tmpsize);
    }
    /* using the EK requires a policy session */
    TPMI_SH_AUTH_SESSION 	sessionHandle;
    if (rc == 0) {
	rc = makePolicySession(tssContext, &sessionHandle);
    }
    /* policy secret satisfies the policy session for the EK primary key */
    if (rc == 0) {
	rc = policySecret(tssContext, sessionHandle);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ActivateCredential,
			 TPM_RS_PW, NULL, 0,
			 sessionHandle, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    *certInfo = out.certInfo;
	    if (vverbose) TSS_PrintAll("activatecredential: decrypted secret:",
				       out.certInfo.t.buffer, out.certInfo.t.size);
	}
	else {
	    flushContext(tssContext, sessionHandle);
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: activatecredential: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}
		
/* makePolicySession() makes a policy session that can be used as an EK authorization

   Returns the policy session handle.
*/

TPM_RC makePolicySession(TSS_CONTEXT *tssContext,
			 TPMI_SH_AUTH_SESSION *sessionHandle)
{
    TPM_RC 			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;

    /* start a policy session */
    if (rc == 0) {
	startAuthSessionIn.sessionType = TPM_SE_POLICY;
	startAuthSessionIn.tpmKey = TPM_RH_NULL;
	startAuthSessionIn.bind = TPM_RH_NULL;
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
	startAuthSessionIn.authHash = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
	startAuthSessionExtra.bindPassword = NULL;
    }   
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*sessionHandle = startAuthSessionOut.sessionHandle;
	if (verbose) printf("INFO: makePolicySession: Policy session handle %08x\n",
			    startAuthSessionOut.sessionHandle);
	if (vverbose) printf("makePolicySession: TPM2_StartAuthSession success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: makePolicySession: TPM2_StartAuthSession failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* makeHmacSession() makes an HMAC session that can be used as an audit session.

   Returns the session handle.
*/

TPM_RC makeHmacSession(TSS_CONTEXT *tssContext,
		       TPMI_SH_AUTH_SESSION *sessionHandle)
{
    TPM_RC 			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;

    /* start a policy session */
    if (rc == 0) {
	startAuthSessionIn.sessionType = TPM_SE_HMAC;
	startAuthSessionIn.tpmKey = TPM_RH_NULL;
	startAuthSessionIn.bind = TPM_RH_NULL;
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
	startAuthSessionIn.authHash = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
	startAuthSessionExtra.bindPassword = NULL;
    }   
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*sessionHandle = startAuthSessionOut.sessionHandle;
	if (verbose) printf("INFO: makeHmacSession: HMAC session handle %08x\n",
			    startAuthSessionOut.sessionHandle);
	if (vverbose) printf("makeHmacSession: TPM2_StartAuthSession success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: makeHmacSession: TPM2_StartAuthSession failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* policySecret() runs a policy secret with TPM_RH_ENDORSEMENT, setting up the policy session to use
   the endorsement hierarchy password.

*/

TPM_RC policySecret(TSS_CONTEXT *tssContext,
		    TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC 			rc = 0;
    PolicySecret_In 		policySecretIn;
    PolicySecret_Out 		policySecretOut;
    
    /* run policy secret over the endorsement auth to satisfy the policy */
    if (rc == 0) {
	policySecretIn.authHandle = TPM_RH_ENDORSEMENT;
	policySecretIn.policySession = sessionHandle;
	policySecretIn.nonceTPM.b.size = 0;
	policySecretIn.cpHashA.b.size = 0;
	policySecretIn.policyRef.b.size = 0;
	policySecretIn.expiration = 0;
    }   
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&policySecretOut, 
			 (COMMAND_PARAMETERS *)&policySecretIn,
			 NULL,
			 TPM_CC_PolicySecret,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("policySecret: TPM2_PolicySecret: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: policySecret: TPM2_PolicySecret: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* signQuote() signs a quote using the attestation keyHandle.

   It returns the quote data and signature.

*/

uint32_t signQuote(TSS_CONTEXT *tssContext,
		   TPM2B_ATTEST *quoted,
		   TPMT_SIGNATURE *signature,
		   TPM_HANDLE keyHandle,	/* attestation key */
		   TPMI_ALG_PUBLIC type,
		   const unsigned char *nonceBin,
		   size_t nonceLen,
		   const TPML_PCR_SELECTION *pcrSelection)
{
    TPM_RC			rc = 0;
    Quote_In 			in;
    Quote_Out 			out;
    
    if (rc == 0) {
	/* Handle of key that will perform quoting */
	in.signHandle = keyHandle;
	/* data supplied by the caller */
	/* FIXME should really come from AK public */
	if (type == TPM_ALG_RSA) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    in.inScheme.scheme = TPM_ALG_RSASSA;	
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
	}
	else if (type == TPM_ALG_ECC) {
	    in.inScheme.scheme = TPM_ALG_ECDSA;
	    in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	}
	else {
	    printf("ERROR: signQuote: unsupported algorithm\n");
	    rc = EXIT_FAILURE;
	}
	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	in.PCRselect.count = 1;
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */
	in.PCRselect = *pcrSelection;
    }
    /* FIXME size check */
    if (rc == 0) {
	memcpy(in.qualifyingData.t.buffer, nonceBin, nonceLen);
	in.qualifyingData.t.size = nonceLen;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Quote,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: quote: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    /* return attestation quote (for debug) and signature */
    if (rc == 0) {
	*quoted = out.quoted;
	*signature = out.signature;
    }
    return rc;
}

/* getAuditDigest() signs an audit digest using the attestation keyHandle.

   It returns the quote data and signature.

*/

uint32_t getAuditDigest(TSS_CONTEXT *tssContext,
			TPM2B_ATTEST *auditInfo,		/* output */
			TPMT_SIGNATURE *signature,		/* output */
			TPM_HANDLE keyHandle,			/* attestation key */
			TPMI_ALG_PUBLIC type,
			TPMI_SH_AUTH_SESSION sessionHandle,	/* input audit session */
			const unsigned char *nonceBin,		/* qualifyingData */
			size_t nonceLen)
{
    TPM_RC			rc = 0;
    GetSessionAuditDigest_In 	in;
    GetSessionAuditDigest_Out	out;
    
    if (rc == 0) {
	/* Handle of key that will perform quoting */
	in.privacyAdminHandle = TPM_RH_ENDORSEMENT;
	in.signHandle = keyHandle;
	in.sessionHandle = sessionHandle;
	/* data supplied by the caller */
	/* FIXME should really come from AK public */
	if (type == TPM_ALG_RSA) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    in.inScheme.scheme = TPM_ALG_RSASSA;	
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
	}
	else if (type == TPM_ALG_ECC) {
	    in.inScheme.scheme = TPM_ALG_ECDSA;
	    in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	}
	else if (keyHandle != TPM_RH_NULL) {
	    printf("ERROR: getAuditDigest: unsupported algorithm\n");
	    rc = EXIT_FAILURE;
	}
    }
    /* FIXME size check */
    if (rc == 0) {
	memcpy(in.qualifyingData.t.buffer, nonceBin, nonceLen);
	in.qualifyingData.t.size = nonceLen;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetSessionAuditDigest,
			 TPM_RS_PW, NULL, 0,	/* privacy admin */
			 TPM_RS_PW, NULL, 0,	/* signing key */
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: getAuditDigest: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    if (vverbose) {
	TPMS_ATTEST tpmsAttest;
	if (rc == 0) {
	    printf("getAuditDigest:\n");
	    uint8_t *tmpBuffer = out.auditInfo.t.attestationData;
	    uint32_t tmpSize = out.auditInfo.t.size;
	    rc = TSS_TPMS_ATTEST_Unmarshalu(&tpmsAttest, &tmpBuffer, &tmpSize);
	}
	if (rc == 0) {
	    TSS_TPMS_ATTEST_Print(&tpmsAttest, 2);
	}
    }
    /* return audit attestation and signature */
    if (rc == 0) {
	*auditInfo = out.auditInfo;
	*signature = out.signature;
    }
    return rc;
}

/* readPcrs() reads all the TPM PCRs.  It reads one PCR at a time.

   It reads the banks specified by pcrSelection, but ignores the bit mask and reads all PCRs.
*/

uint32_t readPcrs(TSS_CONTEXT *tssContext,
		  TPML_PCR_BANKS *pcrBanks,
		  const TPML_PCR_SELECTION *pcrSelection)
{
    TPM_RC			rc = 0;
    PCR_Read_In 		in;
    PCR_Read_Out 		out;
    uint32_t			bank;	/* iterate through PCR banks */

    /* read all banks, one PCR at a time */
    pcrBanks->count = pcrSelection->count;
    in.pcrSelectionIn.count = pcrSelection->count;

    /* set the count and hash algorithm, same for all PCRs */
    for (bank = 0 ; bank < pcrSelection->count ; bank++) {
	pcrBanks->pcrBank[bank].count = IMPLEMENTATION_PCR;
	pcrBanks->pcrBank[bank].hash = pcrSelection->pcrSelections[bank].hash;
	in.pcrSelectionIn.pcrSelections[bank].hash = pcrSelection->pcrSelections[bank].hash;
	in.pcrSelectionIn.pcrSelections[bank].sizeofSelect =
	    pcrSelection->pcrSelections[bank].sizeofSelect;	/* should be 3 */
    }

    uint8_t 	selectByte;	/* all bytes of PCR select */
    uint8_t 	selectBit;	/* bit map within a byte */
    uint32_t	pcrNum;		/* iterate through PCRs */

    /* iterate through each select byte */
    for (selectByte = 0, pcrNum = 0 ; selectByte < (IMPLEMENTATION_PCR/8) ; selectByte++) {
	/* iterate through each bit in the byte */
	for (selectBit = 0 ; selectBit < 8 ; selectBit++, pcrNum++) {

	    for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[0] = 0;
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[1] = 0;
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[2] = 0;
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[selectByte] = 1 << selectBit;
	    }
	    /* call TSS to execute the command */
	    if (rc == 0) {
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&out,
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_CC_PCR_Read,
				 TPM_RH_NULL, NULL, 0);
	    }
	    if (rc == 0) {
		/* iterate through the banks and copy the PCR value to
		   pcrBanks->pcrBank[bank].digests[pcrNum].t. */
		for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {
		    if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA256) {
			pcrBanks->pcrBank[bank].digests[pcrNum].t.size = SHA256_DIGEST_SIZE;
			memcpy(pcrBanks->pcrBank[bank].digests[pcrNum].t.buffer,
			       out.pcrValues.digests[bank].t.buffer,
			       SHA256_DIGEST_SIZE);
		    }
		    else if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA1) {
			pcrBanks->pcrBank[bank].digests[pcrNum].t.size = SHA1_DIGEST_SIZE;
			memcpy(pcrBanks->pcrBank[bank].digests[pcrNum].t.buffer,
			       out.pcrValues.digests[bank].t.buffer,
			       SHA1_DIGEST_SIZE);
		    }
		    else {
			printf("ERROR: readPcrs: does not support algorithm %04x yet\n",
			       pcrSelection->pcrSelections[bank].hash);
			rc = EXIT_FAILURE;
		    }
		}
	    }
	    else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("ERROR: readPcrs: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	    }
	}
    }
    return rc;
}

/* readPcrsA() reads TPM PCRs in an audit session.  It reads one PCR at a time.

   It reads the banks specified by pcrSelection, but ignores the bit mask and reads all PCRs.

   Banks nor ead have the size set to 0.
*/

uint32_t readPcrsA(TSS_CONTEXT *tssContext,
		   TPML_PCR_BANKS *outPcrBanks,			/* output PCR array */
		   TPMI_SH_AUTH_SESSION sessionHandle,		/* input audit session */
		   const TPML_PCR_SELECTION *inPcrSelection)	/* input PCR selection */
{
    TPM_RC			rc = 0;
    PCR_Read_In 		in;
    PCR_Read_Out 		out;
    uint32_t			pcrBank = 0;	/* PCR bank being output, different from bank */
    uint32_t			bank = 0;	/* iterate through PCR banks in pcrSelection */
    uint8_t 			selectByte;	/* iterate through all bytes of PCR select */
    uint8_t 			selectBit = 0;	/* iterate through bit map within a byte */
    uint32_t			pcrNum = 0;	/* iterate through PCRs */

    outPcrBanks->count = 0;	/* count of banks with at least one PCR selected */
    in.pcrSelectionIn.count = 1;	/* do one bank at a time */

    /* iterate through each bank */
    for (bank = 0 ; (rc == 0) && (bank < inPcrSelection->count) ; bank++) {
	int foundPCR = FALSE;	/* a PCR is selected in this bank */
	in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 
	    inPcrSelection->pcrSelections[bank].sizeofSelect;	/* should be 3 */
	in.pcrSelectionIn.pcrSelections[0].hash =
	    inPcrSelection->pcrSelections[bank].hash;
	outPcrBanks->pcrBank[pcrBank].hash = inPcrSelection->pcrSelections[bank].hash;
	
	/* iterate through each select byte */
	for (selectByte = 0, pcrNum = 0 ; selectByte < (IMPLEMENTATION_PCR/8) ; selectByte++) {

	    /* iterate through each bit in the byte */
	    for (selectBit = 0 ; selectBit < 8 ; selectBit++, pcrNum++) {

		/* if the PCR is selcted in the input pcrSelection */
		if (inPcrSelection->pcrSelections[bank].pcrSelect[selectByte]  & (1<<selectBit)) {

		    foundPCR = TRUE;	/* flag that a PCR was found */
		    in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
		    in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
		    in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
		    in.pcrSelectionIn.pcrSelections[0].pcrSelect[selectByte] = 1 << selectBit;
		    /* call TSS to execute the command */
		    if (rc == 0) {
			rc = TSS_Execute(tssContext,
					 (RESPONSE_PARAMETERS *)&out,
					 (COMMAND_PARAMETERS *)&in,
					 NULL,
					 TPM_CC_PCR_Read,
					 sessionHandle, NULL,
					 TPMA_SESSION_AUDIT | TPMA_SESSION_CONTINUESESSION,
					 TPM_RH_NULL, NULL, 0);
		    }
		    /* copy the read PCR value */
		    if (rc == 0) {
			outPcrBanks->pcrBank[pcrBank].pcrUpdateCounter[pcrNum] =
			    out.pcrUpdateCounter;
			if (inPcrSelection->pcrSelections[0].hash == TPM_ALG_SHA256) {
			    outPcrBanks->pcrBank[pcrBank].digests[pcrNum].t.size =
				SHA256_DIGEST_SIZE;
			    memcpy(outPcrBanks->pcrBank[pcrBank].digests[pcrNum].t.buffer,
				   out.pcrValues.digests[0].t.buffer,
				   SHA256_DIGEST_SIZE);
			}
			else if (inPcrSelection->pcrSelections[0].hash == TPM_ALG_SHA1) {
			    outPcrBanks->pcrBank[pcrBank].digests[pcrNum].t.size =
				SHA1_DIGEST_SIZE;
			    memcpy(outPcrBanks->pcrBank[pcrBank].digests[pcrNum].t.buffer,
				   out.pcrValues.digests[0].t.buffer,
				   SHA1_DIGEST_SIZE);
			}
			else {
			    printf("ERROR: readPcrsA: does not support algorithm %04x yet\n",
				   inPcrSelection->pcrSelections[bank].hash);
			    rc = EXIT_FAILURE;
			}
		    }
		    else {
			const char *msg;
			const char *submsg;
			const char *num;
			printf("ERROR: readPcrsA: failed, rc %08x\n", rc);
			TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
			printf("%s%s%s\n", msg, submsg, num);
			rc = EXIT_FAILURE;
		    }
		    /* if tracing is on, trace the session audit digest after each PCR read */
		    if (vverbose) {
			TPM2B_ATTEST auditInfo;
			TPMT_SIGNATURE signature;
			if (rc == 0) {
			    rc = getAuditDigest(tssContext,
						&auditInfo,
						&signature,
						TPM_RH_NULL,	/* no signature needed */
						TPM_ALG_RSA,	/* not used */
						sessionHandle,
						NULL,		/* nonce */
						0);		/* nonce length */
			}
		    }	     
		}
		else {	/* if PCR not selected, mark the PCR response empty */
		    outPcrBanks->pcrBank[pcrBank].digests[pcrNum].t.size = 0;
		}
		outPcrBanks->pcrBank[pcrBank].count++;	/* record that another PCR was read */
	    }
	}
	if (foundPCR) {
	    outPcrBanks->count++;	/* record that at least one PCR was read in this bank */
	    pcrBank++;			/* prepare for the next output bank */
	}
    }
    return rc;
}

TPM_RC flushContext(TSS_CONTEXT *tssContext,
		    TPM_HANDLE handle)
{
    TPM_RC			rc = 0;
    FlushContext_In 		in;

    if (vverbose) printf("flushContext: Entry, handle %08x\n", handle);
    if (rc == 0) {
	in.flushHandle = handle;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("flushContext: TPM2_FlushContext success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: flushcontext: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

TPM_RC policyPCR(TSS_CONTEXT 		*tssContext,
		 TPMI_SH_AUTH_SESSION 	sessionHandle,
		 TPML_PCR_SELECTION	*pcrs)
{
    TPM_RC			rc = 0;
    PolicyPCR_In 		in;

    if (rc == 0) {
	in.policySession = sessionHandle;
	/* NOTE not implemented yet */
	in.pcrDigest.b.size = 0;
	in.pcrs = *pcrs;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyPCR,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("INFO: policyPCR: TPM2_PolicyPCR success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: policyPCR: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

TPM_RC policyCommandCode(TSS_CONTEXT 		*tssContext,
			 TPMI_SH_AUTH_SESSION 	sessionHandle,
			 TPM_CC 		commandCode)
{
    TPM_RC			rc = 0;
    PolicyCommandCode_In 	policyCommandCodeIn;

    if (vverbose) printf("policyCommandCode: Entry\n");
    if (rc == 0) {
	policyCommandCodeIn.policySession = sessionHandle;
	policyCommandCodeIn.code = commandCode;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&policyCommandCodeIn,
			 NULL,
			 TPM_CC_PolicyCommandCode,
			 TPM_RH_NULL, NULL, 0);
    } 
    if (rc == 0) {
	if (vverbose) printf("policyCommandCode: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: policycommandcode: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* loadExternal() runs TPM2_LoadExternal, loading a key public part.

   If name is not NULL, it is returned.

*/

uint32_t loadExternal(TSS_CONTEXT *tssContext,
		      TPM_HANDLE *objectHandle,
		      TPM2B_NAME *name,
		      TPMT_PUBLIC *inPublic)
{
    uint32_t 		rc = 0;
    LoadExternal_In 	loadExternalIn;
    LoadExternal_Out 	loadExternalOut;

    if (vverbose) printf("loadExternal: Entry\n");
    /* load the attestation key */
    if (rc == 0) {
	loadExternalIn.hierarchy = TPM_RH_OWNER;
	loadExternalIn.inPrivate.t.size = 0;			/* only public key */
	loadExternalIn.inPublic.publicArea = *inPublic;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&loadExternalOut,
			 (COMMAND_PARAMETERS *)&loadExternalIn,
			 NULL,
			 TPM_CC_LoadExternal,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*objectHandle = loadExternalOut.objectHandle;
	if (name != NULL) {
	    *name = loadExternalOut.name;	    /* copies the structure contents */
	}
	if (vverbose) printf("loadExternal: TPM2_LoadExternal handle %08x\n",
			     loadExternalOut.objectHandle);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR:loadExternal: TPM2_Load failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}

uint32_t verifySignature(TSS_CONTEXT 		*tssContext,
			 TPMT_TK_VERIFIED	*validation,
			 TPM2B_DIGEST 		*tDigest,
			 TPMT_SIGNATURE 	*tSignature,
			 TPMI_DH_OBJECT 	pubkeyHandle)
{
    uint32_t 			rc = 0;
    VerifySignature_In 		verifySignatureIn;
    VerifySignature_Out 	verifySignatureOut;

    if (rc == 0) {
	verifySignatureIn.keyHandle = pubkeyHandle;
	verifySignatureIn.digest = *tDigest;
	verifySignatureIn.signature = *tSignature;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&verifySignatureOut,
			 (COMMAND_PARAMETERS *)&verifySignatureIn,
			 NULL,
			 TPM_CC_VerifySignature,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*validation = verifySignatureOut.validation;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: verifysignature: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

uint32_t policyAuthorize(TSS_CONTEXT 		*tssContext,
			 TPMI_SH_POLICY		policySession,
			 TPM2B_DIGEST		*approvedPolicy,
			 TPM2B_NONCE		*policyRef,
			 TPM2B_NAME		*keySign,
			 TPMT_TK_VERIFIED	*checkTicket)
{
    uint32_t 			rc = 0;
    PolicyAuthorize_In 		policyAuthorizeIn;

    if (rc == 0) {
	policyAuthorizeIn.policySession = policySession;
	policyAuthorizeIn.approvedPolicy = *approvedPolicy;
	if (policyRef != NULL) {
	    policyAuthorizeIn.policyRef = *policyRef;
	}
	else {
	    policyAuthorizeIn.policyRef.b.size = 0;	/* default empty buffer */
	}
	policyAuthorizeIn.keySign = *keySign;
	policyAuthorizeIn.checkTicket = *checkTicket;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&policyAuthorizeIn,
			 NULL,
			 TPM_CC_PolicyAuthorize,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: policyauthorize: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

uint32_t policyGetDigest(TSS_CONTEXT *tssContext,
			 TPMI_SH_POLICY policySession)
{
    uint32_t 			rc = 0;
    PolicyGetDigest_In 		policyGetDigestIn;
    PolicyGetDigest_Out 	policyGetDigestOut;

    if (rc == 0) {
	policyGetDigestIn.policySession = policySession;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&policyGetDigestOut, 
			 (COMMAND_PARAMETERS *)&policyGetDigestIn,
			 NULL,
			 TPM_CC_PolicyGetDigest,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) TSS_PrintAll("policyGetDigest: policyDigest",
				   policyGetDigestOut.policyDigest.t.buffer,
				   policyGetDigestOut.policyDigest.t.size);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: policyGetDigest: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

