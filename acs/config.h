/********************************************************************************/
/*										*/
/*			TPM 2.0 Attestation - Configuration     		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: config.h 1167 2018-04-18 18:38:04Z kgoldman $		*/
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

#ifndef CONFIG_H
#define CONFIG_H

#include <tss2/tss.h>

/* the same value Windows 10 uses */
#define SRK_HANDLE 0x81000001

/* files to store attestation key public and private parts */
#define AK_RSA_PUB_FILENAME	"akrsapub"
#define AK_RSA_PRIV_FILENAME	"akrsapriv"
#define AK_EC_PUB_FILENAME	"akecpub"
#define AK_EC_PRIV_FILENAME	"akecpriv"

#ifdef TPM_TPM12
#define AK_FILENAME		"aik"
#endif

/* the largest, for file name length checks */
#define AK_FILENAME_MAX		AK_RSA_PRIV_FILENAME


/* SW TPM EK certificate issuer */
#define CA_KEY		"cakey.pem"
#define CA_PASSWORD	"rrrr"

/* Server privacy CA */
#define PCA_KEY		"pcakey.pem"	/* signing key */
#define PCA_PASSWORD	"rrrr"		/* password for signing key */
#define PCA_CERT	"pcacert.pem"	/* self-signed certificate */

/* Debug tools */
#define CLIENT_NONCE_FILENAME		"tmpnonce.txt"
#define CLIENT_PCRSELECT_FILENAME	"tmppcrselect.txt"

/* the TPM TPML_DIGEST is limited to 8 PCRs because of the buffer sizes.  Define a new
   structure here that can hold all PCRs.
*/

typedef struct {
    UINT32		count;			/* number of digests for this bank */
    TPMI_ALG_HASH	hash;			/* the hash algorithm associated with the bank */
    TPM2B_DIGEST	digests[IMPLEMENTATION_PCR];	/* a list of digests */
} TPML_PCR_BANK;

/* all PCRs for all banks */

typedef struct {
    UINT32		count;			/* number of banks */
    TPML_PCR_BANK	pcrBank[HASH_COUNT];
} TPML_PCR_BANKS;

#ifdef TPM_TPM12

typedef struct {
    UINT32		count;			/* number of digests for this bank */
    TPM_DIGEST 		digests[IMPLEMENTATION_PCR];	/* a list of digests */
} TPML_PCR12_BANK;



#endif


#endif
