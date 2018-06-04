/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client Side Local Functions		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientlocal.h 975 2017-03-27 22:10:34Z kgoldman $		*/
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

#ifndef CLIENTLOCAL_H
#define CLIENTLOCAL_H

#include <stdint.h>

#include "config.h"

TPM_RC createEnrollmentData(char *tpmVendor,
			    uint16_t *ekCertLength,
			    unsigned char **ekCertificate,	
			    TPM2B_PRIVATE *attestPriv,
			    TPM2B_PUBLIC *attestPub,
			    uint16_t *attestPubLength,
			    unsigned char **attestPubBin,	
			    TPMI_RH_NV_INDEX nvIndex);
TPM_RC recoverAttestationKeyCertificate(TPM2B_DIGEST 	*certInfo,
					TPM2B_PRIVATE 	*attestPriv,
					TPM2B_PUBLIC 	*attestPub,
					TPMI_RH_NV_INDEX ekCertIndex,
					unsigned char 	*credentialBlobBin,
					size_t 		credentialBlobBinSize,
					unsigned char 	*secretBin,
					size_t 		secretBinSize);

TPM_RC runQuote(TPML_PCR_BANKS *pcrBanks,
		TPM2B_ATTEST *quoted,
		TPMT_SIGNATURE *signature,
		char *boottimeString,
		size_t boottimeStringLen,
		const unsigned char *nonceBin,
		size_t nonceLen,
		const TPML_PCR_SELECTION *pcrSelection,
		TPM2B_PRIVATE *attestPriv,
		TPM2B_PUBLIC *attestPub);

TPM_RC retrieveTPMLog(const char *biosInputFilename);


#endif
