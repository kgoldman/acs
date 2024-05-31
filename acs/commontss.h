/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common TSS Functions	  		*/
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

#ifndef COMMONTSS_H
#define COMMONTSS_H

#include <ibmtss/tss.h>

TPM_RC getTpmVendor(TSS_CONTEXT *tssContext,
		    char 	*tpmVendor);
TPM_RC getCapSrk(TSS_CONTEXT 	*tssContext,
		 int   		*exists);
TPM_RC createSrk(TSS_CONTEXT 	*tssContext,
		 TPM_HANDLE 	*handle);
TPM_RC persistSrk(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	srkHandle);
TPM_RC createAttestationKey(TSS_CONTEXT 	*tssContext,
			    TPMI_RH_NV_INDEX 	nvIndex,
			    TPM2B_PRIVATE 	*attestPriv,
			    TPM2B_PUBLIC 	*attestPub,
			    uint16_t 		*attestPubLength,
			    unsigned char 	**attestPubBin);
TPM_RC loadObject(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	*handle,
		  TPM2B_PRIVATE *attestPriv,
		  TPM2B_PUBLIC 	*attestPub);
TPM_RC activatecredential(TSS_CONTEXT *tssContext,
			  TPM2B_DIGEST *certInfo,
			  TPM_HANDLE activateHandle,
			  TPM_HANDLE ekKeyHandle,
			  TPMI_RH_NV_INDEX ekCertIndex,
			  TPMI_ALG_HASH  sessionHashAlg,
			  unsigned char *credentialBlobBin,
			  size_t credentialBlobBinSize,
			  unsigned char *secretBin,
			  size_t secretBinSize);
TPM_RC makePolicySession(TSS_CONTEXT *tssContext,
			 TPMI_SH_AUTH_SESSION *sessionHandle,
			 TPMI_ALG_HASH sessionHashAlg);
TPM_RC makeHmacSession(TSS_CONTEXT *tssContext,
		       TPMI_SH_AUTH_SESSION *sessionHandle);
TPM_RC policySecret(TSS_CONTEXT *tssContext,
		    TPMI_SH_AUTH_SESSION sessionHandle);
TPM_RC policyB(TSS_CONTEXT *tssContext,
	       TPMI_SH_AUTH_SESSION sessionHandle,
	       TPMI_ALG_HASH sessionHashAlg);
TPM_RC flushContext(TSS_CONTEXT 	*tssContext,
		    TPM_HANDLE 		handle);
TPM_RC policyPCR(TSS_CONTEXT 		*tssContext,
		 TPMI_SH_AUTH_SESSION 	sessionHandle,
		 TPML_PCR_SELECTION	*pcrs);
TPM_RC policyCommandCode(TSS_CONTEXT 		*tssContext,
			 TPMI_SH_AUTH_SESSION 	sessionHandle,
			 TPM_CC 		commandCode);
uint32_t readPcrs(TSS_CONTEXT *tssContext,
		  TPML_PCR_BANKS *pcrBanks,
		  const TPML_PCR_SELECTION *pcrSelection);
uint32_t readPcrsA(TSS_CONTEXT *tssContext,
		   TPML_PCR_BANKS *outPcrBanks,
		   TPMI_SH_AUTH_SESSION sessionHandle,
		   const TPML_PCR_SELECTION *pcrSelection);
uint32_t signQuote(TSS_CONTEXT *tssContext,
		   TPM2B_ATTEST *quoted,
		   TPMT_SIGNATURE *signature,
		   TPM_HANDLE keyHandle,
		   TPMI_ALG_PUBLIC type,
		   const unsigned char *nonceBin,
		   size_t nonceLen,
		   const TPML_PCR_SELECTION *pcrSelection);
uint32_t getAuditDigest(TSS_CONTEXT *tssContext,
			TPM2B_ATTEST *auditInfo,
			TPMT_SIGNATURE *signature,
			TPM_HANDLE keyHandle,
			TPMI_ALG_PUBLIC type,
			TPMI_SH_AUTH_SESSION sessionHandle,
			const unsigned char *nonceBin,
			size_t nonceLen);
uint32_t loadExternal(TSS_CONTEXT *tssContext,
		      TPM_HANDLE *objectHandle,
		      TPM2B_NAME *name,
		      TPMT_PUBLIC *inPublic);
uint32_t verifySignature(TSS_CONTEXT 		*tssContext,
			 TPMT_TK_VERIFIED	*validation,
			 TPM2B_DIGEST 		*tDigest,
			 TPMT_SIGNATURE 	*tSignature,
			 TPMI_DH_OBJECT 	pubkeyHandle);
uint32_t policyAuthorize(TSS_CONTEXT 		*tssContext,
			 TPMI_SH_POLICY		policySession,
			 TPM2B_DIGEST		*approvedPolicy,
			 TPM2B_NONCE		*policyRef,
			 TPM2B_NAME		*keySign,
			 TPMT_TK_VERIFIED	*checkTicket);
uint32_t policyGetDigest(TSS_CONTEXT *tssContext,
			 TPMI_SH_POLICY policySession);
#endif
