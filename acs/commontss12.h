/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common TSS Functions	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commontss12.h 1159 2018-04-17 15:10:01Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016.						*/
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

#ifndef COMMONTSS12_H
#define COMMONTSS12_H

#include <tss2/tss.h>

TPM_RC getTpmVendor12(TSS_CONTEXT *tssContext,
		      char 	*tpmVendor);
TPM_RC startOIAP(TSS_CONTEXT *tssContext,
		 TPM_AUTHHANDLE *sessionHandle);
TPM_RC startOSAP(TSS_CONTEXT *tssContext,
		 TPM_AUTHHANDLE *sessionHandle,
		 UINT32 entityValue,
		 const char *password);
TPM_RC flushSpecific(TSS_CONTEXT *tssContext,
		     TPM_HANDLE handle,
		     TPM_RESOURCE_TYPE resourceType);
TPM_RC ownerReadInternalPub(TSS_CONTEXT *tssContext,
			    TPM_PUBKEY *ekPub,
			    TPM_KEY_HANDLE keyHandle,
			    TPM_AUTHHANDLE sessionHandle,
			    const char *ownerPassword);
TPM_RC createAttestationKey12(TSS_CONTEXT *tssContext,
			      TPM_KEY12 *attestKey,
			      TPM_AUTHHANDLE sessionHandle0,
			      const char *srkPassword,
			      const char *ownerPassword);
TPM_RC loadObject12(TSS_CONTEXT *tssContext,
		    TPM_HANDLE 	*handle,
		    TPM_KEY12 	*attestKey,
		    TPM_AUTHHANDLE sessionHandle0,
		    const char 	*parentPassword);
uint32_t readPcrs12(TSS_CONTEXT *tssContext,
		    TPML_PCR12_BANK *pcrBank,
		    const TPM_PCR_SELECTION *pcrSelection);
uint32_t signQuote12(TSS_CONTEXT *tssContext,
		     TPM_PCR_INFO_SHORT *pcrData,
		     uint32_t *versionInfoSize,
		     TPM_CAP_VERSION_INFO *versionInfo,
		     uint32_t *signatureSize,
		     uint8_t *signature,
		     TPM_HANDLE keyHandle,
		     const unsigned char *nonceBin,
		     const TPM_PCR_SELECTION *pcrSelection,
		     TPM_AUTHHANDLE sessionHandle0,
		     const char *keyPassword);

#if 0
TPM_RC getCapSrk(TSS_CONTEXT 	*tssContext,
		 int   		*exists);
TPM_RC createSrk(TSS_CONTEXT 	*tssContext,
		 TPM_HANDLE 	*handle);
TPM_RC persistSrk(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	srkHandle);
TPM_RC activatecredential(TSS_CONTEXT *tssContext,
			  TPM2B_DIGEST *certInfo,
			  TPM_HANDLE activateHandle,
			  TPM_HANDLE keyHandle,
			  unsigned char *credentialBlobBin,
			  size_t credentialBlobBinSize,
			  unsigned char *secretBin,
			  size_t secretBinSize);
TPM_RC makePolicySession(TSS_CONTEXT *tssContext,
			 TPMI_SH_AUTH_SESSION *sessionHandle);
TPM_RC flushContext(TSS_CONTEXT 	*tssContext,
		    TPM_HANDLE 		handle);
uint32_t loadExternal(TSS_CONTEXT *tssContext,
		      TPM_HANDLE *objectHandle,
		      TPM2B_NAME *name,
		      TPMT_PUBLIC *inPublic);
uint32_t verifySignature(TSS_CONTEXT 		*tssContext,
			 TPMT_TK_VERIFIED	*validation,
			 TPM2B_DIGEST 		*tDigest,
			 TPMT_SIGNATURE 	*tSignature,
			 TPMI_DH_OBJECT 	pubkeyHandle);
#endif
#endif
