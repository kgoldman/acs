/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client Side Local Functions		*/
/*			     Written by Chris Engel				*/
/*		       								*/
/*            $Id: clientPvmLocal.c 1677 2022-02-03 18:24:43Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2017, 2018					*/
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
#include <time.h>
#ifdef TPM_ACS_PVM_INBAND
#include <librtas.h>
#endif

#include "clientsocket.h"
#include "clientlocal.h"
#include "acsPvmTypes.h"
#include <ibmtss/tssutils.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

/* local function prototypes */
TPM_RC retrieveTPMLogSize(uint8_t logInstance, uint32_t *logHandle, uint32_t * logLength);

extern int verbose;
extern int vverbose;

#ifdef TPM_ACS_PVM_REMOTE
extern char* g_sphost;
extern char* g_spport;
#endif

static void fillAcsPvmCommandHeader(uint8_t command,
                                    AcsPvmCommandRequest *cmdBuffer,
                                    uint32_t cmdLength);


static uint32_t sendAcsPvmCommand(uint8_t *cmdBuffer,
                                  uint32_t cmdLength,
                                  uint8_t **rspBuffer,
                                  uint32_t *rspLength);

static void fillAcsPvmCommandHeader(uint8_t command,
                                    AcsPvmCommandRequest *cmdBuffer,
                                    uint32_t cmdLength)
{
    uint32_t randomValue;
    // generate a random value which can be used as correlator
    randomValue = rand();

    if (cmdBuffer !=NULL)
    {
        // Fill in the acs command parameters
        cmdBuffer->header.version = AcsPvmStructureVersion;
        cmdBuffer->header.command = command;
        cmdBuffer->header.TCGVersionMajor = AcsPvmTCGVersionMajor;
        cmdBuffer->header.TCGVersionMinor = AcsPvmTCGVersionMinor;

        // Fill the correlator data
        cmdBuffer->header.correlator = htobe32(randomValue);
        cmdBuffer->header.length = htobe32(cmdLength);
    }
}

#ifdef TPM_ACS_PVM_REMOTE
static uint32_t sendViaSocket(uint8_t *cmdBuffer,
                              uint32_t cmdLength,
                              uint8_t **rspBuffer,
                              uint32_t *rspLength)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    short spport = 30015;
    if (NULL != g_spport) {
		sscanf(g_spport, "%hu", &spport);
    }

    rc = Socket_Process(rspBuffer, rspLength,     /* freed by caller */
                        g_sphost, spport,
                        cmdBuffer, cmdLength);

    // caller frees rspBuffer
    return rc;
}
#endif
#ifdef TPM_ACS_PVM_INBAND
static uint32_t sendViaRtas(uint8_t *cmdBuffer,
			    uint32_t cmdLength,
			    uint8_t **rspBuffer,
			    uint32_t *rspLength)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int seq_num = 1;
    int next_seq_num = 0;
    int rtas_rc = 0;
    const uint32_t BUFSIZE = 64*1024;
    const uint32_t REQSIZE = 4*1024; // 4K rtas max request size

    if (cmdLength > REQSIZE) {
	printf("ERROR : sendViaRtas: Command length too long : %d\n", cmdLength);
	return TPM_RC_FAILURE;
    }

    uint8_t* readBuffer = (uint8_t*)malloc(BUFSIZE); // 64K, freed by caller
    *rspBuffer = readBuffer;
    *rspLength = 0;

    if (readBuffer) {
	// Copy over the command into the responseBuffer to send in
	memcpy(readBuffer, cmdBuffer, cmdLength);
        char* bufPtr = (char*)readBuffer;
	int bufLen = BUFSIZE;
        int curLen = 0;
	do {
            curLen = ((int)REQSIZE > bufLen ? bufLen : (int)REQSIZE);
            rtas_rc = rtas_physical_attestation(bufPtr, seq_num, &next_seq_num, &curLen);
	    if (vverbose) {
		printf("RTAS RESPONSE : Seq %d, NextSeq %d, Length %d, RC %d\n",
		       seq_num, next_seq_num, *rspLength, rtas_rc);
	    }
	    /* The response status is pushed into the rtas_rc.  A status of 1 indicates there is
	       more data to retrieve, allow that */
	    if (rtas_rc && !(rtas_rc == 1 && next_seq_num > 1)) {
		printf("ERROR : sendViaRtas: rtas call failed : %d\n", rtas_rc);
		rc = TPM_RC_FAILURE;
		break;
	    }
	    *rspLength += curLen;
	    bufPtr += curLen;
	    bufLen -= curLen;
	    seq_num = next_seq_num;

	} while (next_seq_num != 1 &&
		 bufLen > 0);
    }

    // caller frees rspBuffer
    return rc;
}
#endif


static uint32_t sendAcsPvmCommand(uint8_t *cmdBuffer,
                                  uint32_t cmdLength,
                                  uint8_t **rspBuffer,
                                  uint32_t *rspLength)
{
    TPM_RC  rc = TPM_RC_SUCCESS;
    AcsPvmCommandRequestHeader* cmdReq = (AcsPvmCommandRequestHeader*)cmdBuffer;
    AcsPvmCommandResponseHeader* cmdRes = NULL;

    if (vverbose) {
        printf("ACS PVM Processing Command :");
        uint32_t byte = 0;
        for (byte = 0; byte < cmdLength; byte++) {
            if ((byte % 16 == 0)) printf("\n%03X: ", byte);
            printf("%02X ", cmdBuffer[byte]);
        }
        printf("\n");
    }

#ifdef TPM_ACS_PVM_REMOTE
    /* send the raw ACS command and receive the response */
    rc = sendViaSocket(cmdBuffer, cmdLength,
                       rspBuffer, rspLength);
#else
    rc = sendViaRtas(cmdBuffer, cmdLength,
		     rspBuffer, rspLength);
#endif

    if (rc == 0 && vverbose) {
        printf("ACS PVM Return Response :");
        uint32_t byte  = 0;
        for (byte = 0; byte < *rspLength; byte++) {
            if ((byte % 16 == 0)) printf("\n%03X: ", byte);
                printf("%02X ", ((*rspBuffer)[byte]));
        }
        printf("\n");
    }


    // Ensure at least we have received 8 bytes of response data
    if ((rc == 0) &&
        ((*rspLength < 8) || NULL == rspBuffer))
    {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0)
    {
        cmdRes = (AcsPvmCommandResponseHeader*)*rspBuffer;
        if ( AcsPvmStatus_Success != be32toh(cmdRes->status))
        {
            printf("ERROR: Command returned a failure : %08X\n",
                   be32toh(cmdRes->status));
            rc = be32toh(cmdRes->status);
            if (AcsPvmStatus_AccessDenied == rc)
            {
                printf("ERROR: Access has been denied to physical attestation\n");
            }
        }
        else if (be32toh(cmdRes->length) != *rspLength)
        {
            printf("ERROR: Command response length mismatch : %d:%d\n",
                   be32toh(cmdRes->length),*rspLength);
            rc = TPM_RC_FAILURE;
        }
        else if (be32toh(cmdRes->length) < sizeof(AcsPvmCommandResponseHeader))
        {
            printf("ERROR: Command response too short : %d\n", be32toh(cmdRes->length));
            rc = TPM_RC_FAILURE;
        } else if (cmdReq->correlator != cmdRes->correlator)
        {
            printf("ERROR: Command response correlator mismatch : %08X:%08X\n",
                   cmdReq->correlator, cmdRes->correlator);
            rc = TPM_RC_FAILURE;
        }
    }
    return rc;
}

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

TPM_RC createEnrollmentData(char *tpmVendor,            /* freed by caller */
                uint16_t *ekCertLength,
                unsigned char **ekCertificate,          /* freed by caller */
                TPM2B_PRIVATE *attestPriv,
                TPM2B_PUBLIC *attestPub,
                uint16_t *attestPubLength,
                unsigned char **attestPubBin,	/* freed by caller */
                TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC  rc = TPM_RC_SUCCESS;

    uint8_t *cmdBuffer = NULL;
    uint32_t cmdLength = 0;
    uint32_t rspLength = 0;
    uint8_t  *rspBuffer = NULL;                     /* freed @2 */

    cmdBuffer = malloc(AcsPvmMaxCommandRequestSize);
    cmdLength = sizeof(AcsPvmCommandRequestHeader);

    AcsPvmCommandRequest *cmdReq = (AcsPvmCommandRequest *) cmdBuffer;

    if (NULL == cmdReq)
    {
        printf("ERROR: Unable to allocate request buffer\n");
        rc = TPM_RC_FAILURE;
    }

    fillAcsPvmCommandHeader(AcsPvmCommandGenerateAttestationKeyPair, cmdReq, cmdLength);

    BYTE* payload = (BYTE*)&cmdReq->payLoad;
    INT32 payloadSize = AcsPvmMaxCommandRequestSize - sizeof(AcsPvmCommandRequestHeader);
    uint16_t written = 0;

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPMI_RH_NV_INDEX_Marshal(&nvIndex, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        cmdLength = cmdLength+written;
        cmdReq->header.length = htobe32(cmdLength);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        rc = sendAcsPvmCommand(cmdBuffer, cmdLength, &rspBuffer, &rspLength);
    }
    /* parse response raw stream */
    if (rc == 0)
    {
        AcsPvmCommandResponse *cmdRes = (AcsPvmCommandResponse *) rspBuffer;

        INT32 payloadSize = be32toh(cmdRes->header.length) - sizeof(AcsPvmCommandResponseHeader);

        BYTE* payload = (BYTE*)&cmdRes->payLoad;
        if (TPM_RC_SUCCESS == rc)
        {
            rc = Array_Unmarshal((BYTE*)tpmVendor, AcsTpmVendorStringLength, &payload, &payloadSize);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            rc = TPM2B_PRIVATE_Unmarshal(attestPriv, &payload, &payloadSize);
        }
        if (TPM_RC_SUCCESS == rc)
        {
            rc = TPM2B_PUBLIC_Unmarshal(attestPub, &payload, &payloadSize, FALSE);
        }
        if (TPM_RC_SUCCESS == rc)
        {
            rc = UINT16_Unmarshal(ekCertLength, &payload, &payloadSize);
        }
        if (TPM_RC_SUCCESS == rc)
        {
            rc = TSS_Malloc(ekCertificate, *ekCertLength);

            if (TPM_RC_SUCCESS == rc)
            {
                rc = Array_Unmarshal((BYTE*)*ekCertificate, *ekCertLength, &payload, &payloadSize);
            }
        }

        if (TPM_RC_SUCCESS == rc)
        {
            Create_Out out;
            out.outPublic = *attestPub;
            rc = TSS_Structure_Marshal(attestPubBin,		/* freed by caller */
			                    	   attestPubLength,
				                       &out.outPublic.publicArea,
				                       (MarshalFunction_t)TSS_TPMT_PUBLIC_Marshalu);
        }
        if (TPM_RC_SUCCESS == rc)
        {
            if (verbose)
                printf("INFO: createEnrollmentData Command Success\n");

        }
        else
        {
            if (verbose)
	      printf("ERROR: createEnrollmentData Command Failed : %X\n",rc);
        }

    }
    else
    {
        printf("ERROR: Unable to send AcsPvmCommand\n");
    }

    free (cmdBuffer);
    free (rspBuffer);
    cmdBuffer = NULL;
    rspBuffer = NULL;
    return rc;

}

/* recoverAttestationKeyCertificate() recreates the primary EK, loads the attestation key pair, and
   then runs activate credential to recover the challenge from the credential blob.

   Returns the recovered challenge.

   /// Recover attestation key certificate
   /// @param[out] certInfo Recovered symmetric key
   /// @param[in] attestPriv Attestation private key
   /// @param[in] attestPub Attestation public key
   /// @param[in] credentialBlobBin Credential blob from server MakeCredential
   /// @param[in] credentialBlobBinSize Byte size of credentialBlobBin
   /// @param[in] secretBin Secret from server MakeCredential
   /// @param[in] secretBinSize Byte size of secretBin
*/

TPM_RC recoverAttestationKeyCertificate(TPM2B_DIGEST *certInfo,
                                        TPM2B_PRIVATE *attestPriv,
                                        TPM2B_PUBLIC *attestPub,
                                        TPMI_RH_NV_INDEX ekCertIndex,
                                        unsigned char *credentialBlobBin,
                                        size_t credentialBlobBinSize,
                                        unsigned char *secretBin,
                                        size_t secretBinSize)
{
    TPM_RC  rc = TPM_RC_SUCCESS;

    uint8_t *cmdBuffer = NULL;
    uint32_t cmdLength = 0;
    uint32_t rspLength = 0;
    uint8_t  *rspBuffer = NULL;                     /* freed @2 */

    cmdBuffer = malloc(AcsPvmMaxCommandRequestSize);
    cmdLength = sizeof(AcsPvmCommandRequestHeader);

    AcsPvmCommandRequest *cmdReq = (AcsPvmCommandRequest *) cmdBuffer;

    if (NULL == cmdReq)
    {
        printf("ERROR: Unable to allocate request buffer\n");
        rc = 1;
    }

    fillAcsPvmCommandHeader(AcsPvmCommandRecoverAttestationKey, cmdReq, cmdLength);

    BYTE* payload = (BYTE*)&cmdReq->payLoad;
    INT32 payloadSize = AcsPvmMaxCommandRequestSize - sizeof(AcsPvmCommandRequestHeader);
    uint16_t written = 0;

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPMI_RH_NV_INDEX_Marshal(&ekCertIndex, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPM2B_PRIVATE_Marshal(attestPriv, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPM2B_PUBLIC_Marshal(attestPub, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        if ( (credentialBlobBinSize <= sizeof(TPM2B_ID_OBJECT)) &&
             ((size_t)payloadSize >= credentialBlobBinSize) )
        {
            memcpy(payload, credentialBlobBin, credentialBlobBinSize);
            payload += credentialBlobBinSize;
            written += credentialBlobBinSize;
            payloadSize -=credentialBlobBinSize;
        }
        else
        {
            rc = TPM_RC_SIZE;
            if (verbose)
                printf("ERROR: recoverAttestationKeyCertificate "
		       "credentialBlobBinSize > TPM2B_ID_OBJECT size \n");
        }
    }

    if (TPM_RC_SUCCESS == rc)
    {
        if ( (secretBinSize <= sizeof(TPM2B_ENCRYPTED_SECRET)) &&
             ((size_t)payloadSize >= secretBinSize) )
        {
            memcpy(payload, secretBin, secretBinSize);
            payload += secretBinSize;
            written += secretBinSize;
            payloadSize -= secretBinSize;
        }
        else
        {
            rc = TPM_RC_SIZE;
            if (verbose)
                printf("ERROR: recoverAttestationKeyCertificate "
		       "secretBinSize > TPM2B_ENCRYPTED_SECRET size \n");

        }
    }

    if (TPM_RC_SUCCESS == rc)
    {
        cmdLength = cmdLength+written;
        cmdReq->header.length = htobe32(cmdLength);
    }

    rc = sendAcsPvmCommand(cmdBuffer, cmdLength, &rspBuffer, &rspLength);

    /* parse response raw stream */
    if (rc == 0)
    {
        AcsPvmCommandResponse *cmdRes = (AcsPvmCommandResponse *) rspBuffer;
        INT32 payloadSize = be32toh(cmdRes->header.length) - sizeof(AcsPvmCommandResponseHeader);

        BYTE* payload = (BYTE*)&cmdRes->payLoad;
        if (TPM_RC_SUCCESS == rc)
        {
            rc = TPM2B_DIGEST_Unmarshal(certInfo, &payload, &payloadSize);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            if (verbose)
                printf("INFO: recoverAttestationKeyCertificate Command Success\n");

        }
        else
        {
            if (verbose)
	      printf("ERROR: recoverAttestationKeyCertificate Command Failed : %X\n",rc);
        }

    }
    else
    {
        printf("ERROR: Unable to send AcsPvmCommand - recoverAttestationKeyCertificate\n");
    }
    free (cmdBuffer);
    free (rspBuffer);
    cmdBuffer = NULL;
    rspBuffer = NULL;
    return rc;
}

/* runQuote() runs the TPM quote.  Loads a key whose public and private parts are at AK_PUB_FILENAME
   and AK_PRIV_FILENAME, under the parent at SRK_HANDLE.

   Returns the signature, quote data, and PCRs.

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
                TPM2B_PRIVATE *attestPriv,              /* quote signing key */
                TPM2B_PUBLIC *attestPub)
{
    TPM_RC  rc = TPM_RC_SUCCESS;

    uint8_t *cmdBuffer = NULL;
    uint32_t cmdLength = 0;
    uint32_t rspLength = 0;
    uint8_t  *rspBuffer = NULL;                     /* freed @2 */

    TPML_PCR_SELECTION pcrSelectionRcvd;

    cmdBuffer = malloc(AcsPvmMaxCommandRequestSize);	/* return checked after cast to cmdReq */
    cmdLength = sizeof(AcsPvmCommandRequestHeader);

    AcsPvmCommandRequest *cmdReq = (AcsPvmCommandRequest *) cmdBuffer;

    if (NULL == cmdReq)
    {
        printf("ERROR: Unable to allocate request buffer\n");
        rc = TPM_RC_FAILURE;
    }

    fillAcsPvmCommandHeader(AcsPvmCommandQuote, cmdReq, cmdLength);

    BYTE* payload = (BYTE*)&cmdReq->payLoad;
    INT32 payloadSize = AcsPvmMaxCommandRequestSize - sizeof(AcsPvmCommandRequestHeader);
    uint16_t written = 0;

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPM2B_PRIVATE_Marshal(attestPriv, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPM2B_PUBLIC_Marshal(attestPub, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_TPML_PCR_SELECTION_Marshal( (TPML_PCR_SELECTION *)pcrSelection,
					     &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        TPM2B_DATA nonce;
        if (nonceLen <= (sizeof(nonce)-sizeof(nonce.b.size)))
        {
            nonce.b.size = nonceLen;
            memcpy(nonce.b.buffer, nonceBin, nonce.b.size);
            rc = TSS_TPM2B_DATA_Marshal(&nonce, &written, &payload, &payloadSize);
        }
        else
        {
            rc = TPM_RC_SIZE;
            if (verbose)
                printf("ERROR: runQuote nonceLen > TPM2B_DATA size \n");
        }
    }

    if (TPM_RC_SUCCESS == rc)
	{
	    // Force fetch of all PCRs not just selected
	    // This is required to support the ACS server design
	    BOOL fetchAll = TRUE;
	    rc = TSS_UINT8_Marshal((UINT8*)&fetchAll, &written, &payload, &payloadSize);
	}

    if (TPM_RC_SUCCESS == rc)
	{
	    cmdLength = cmdLength+written;
	    cmdReq->header.length = htobe32(cmdLength);
	}

    if (TPM_RC_SUCCESS == rc)
    {
        rc = sendAcsPvmCommand(cmdBuffer, cmdLength, &rspBuffer, &rspLength);
    }

    /* Check for the special case of invalid attestation keys for this TPM */
    if (AcsPvmStatus_InvalidAttestationKeys == (rc & AcsPvmStatus_StatusMask))
    {
        printf("ERROR: The host was unable to load the attestation keys provided.\n");
        printf("ERROR: This could be caused by targeting the wrong host or if a TPM"
	       "failover recovery has occurred.\n");
        printf("ERROR: You may need to re-enroll or ensure you are targetting the "
	       "correct system\n");
    }

    /* parse response raw stream */
    if (TPM_RC_SUCCESS == rc)
    {
        AcsPvmCommandResponse *cmdRes = (AcsPvmCommandResponse *) rspBuffer;
        INT32 payloadSize = be32toh(cmdRes->header.length) - sizeof(AcsPvmCommandResponseHeader);

        BYTE* payload = (BYTE*)&cmdRes->payLoad;
        if (TPM_RC_SUCCESS == rc)
        {
            // PowerVM returns the boot time during the quote but this client
            //  is not able to consume it at this point so just throw it away
            char boottimeString[AcsPvmBootTimeSize];
            rc = Array_Unmarshal((BYTE*)boottimeString, AcsPvmBootTimeSize,
                                 &payload, &payloadSize);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            rc = TPM2B_ATTEST_Unmarshal(quoted, &payload, &payloadSize);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            rc = TPMT_SIGNATURE_Unmarshal(signature, &payload, &payloadSize, NO);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            // We need to allow the caller to request more than the remote side can support.
            // So we just need to ensure the pcrSelectionRcvd # of digests matches the # of
            // digests returned
            uint32_t hash = 0;
            uint8_t byte = 0;
            uint8_t pcrBit = 0;
            uint32_t numPcrsSelected = 0;
            uint32_t numPcrs = 0;

            if (TPM_RC_SUCCESS == rc)
            {
                rc = TPML_PCR_SELECTION_Unmarshal(&pcrSelectionRcvd, &payload, &payloadSize);
            }

            if (TPM_RC_SUCCESS == rc)
            {
                // check how many pcrs selected
                for (hash = 0; hash < pcrSelectionRcvd.count; hash ++)
                {
                    for (byte = 0; byte < pcrSelectionRcvd.pcrSelections[hash].sizeofSelect; byte ++)
                    {
                        for (pcrBit = 0; pcrBit < 8; pcrBit ++)
                        {
                            if (pcrSelectionRcvd.pcrSelections[hash].pcrSelect[byte] &
				(0x01 << pcrBit))
                            {
                                numPcrsSelected++;
                            }
                        }
                    }
                }
            }
            if (TPM_RC_SUCCESS == rc)
            {
                rc = UINT32_Unmarshal(&numPcrs, &payload, &payloadSize);
            }
            // check if requested pcrs received are all received
            if (numPcrs != numPcrsSelected)
            {
                rc = TPM_RC_SIZE;
                if (verbose)
                    printf("ERROR: numPcrs (%d) != numPcrsSelected (%d) \n",
                           numPcrs, numPcrsSelected);
            }

            // Attestation client is not using the returned PCRs, so just remove
            TPML_PCR_BANKS pcrBanks;
            if (TPM_RC_SUCCESS == rc)
            {
                uint32_t bank = 0;
                //Initialize the pcr banks structure
                memset(&pcrBanks,0,sizeof(TPML_PCR_BANKS));

                // fill th pcrBanks structure with incoming digests based on the count in
                // pcrSelection received
                // the count in the pcr selection list and the pcr bank count will be always
                // same as they are each hash method
                for (hash = 0; (hash < pcrSelectionRcvd.count) && (TPM_RC_SUCCESS == rc); hash ++)
                {
                    uint32_t digest = 0;
                    pcrBanks.pcrBank[bank].hash = pcrSelectionRcvd.pcrSelections[hash].hash;
                    for (byte = 0; byte < pcrSelectionRcvd.pcrSelections[hash].sizeofSelect; byte ++)
                    {
                        for (pcrBit = 0; (pcrBit < 8) && (TPM_RC_SUCCESS == rc); pcrBit ++)
                        {
                            // the below condition can be enabled if we are interesetd in only
                            // specific pcrs requested/received
                            if (pcrSelectionRcvd.pcrSelections[hash].pcrSelect[byte] &
                                (0x01 << pcrBit))
                            {
                                rc = TPM2B_DIGEST_Unmarshal
                                    (&(pcrBanks.pcrBank[bank].digests[digest]),
                                     &payload, &payloadSize);
                                if (rc != TPM_RC_SUCCESS)
                                {
                                    break;
                                }
                            }
                            digest++;
                        }
                        if (rc != TPM_RC_SUCCESS)
                        {
                            break;
                        }
                    }
                    if (rc != TPM_RC_SUCCESS)
                    {
                        break;
                    }

                    // update the pcr bank count with digests
                    pcrBanks.pcrBank[bank].count = digest;

                    bank++;
                    pcrBanks.count++;
                }
            }
        }

        if (TPM_RC_SUCCESS == rc)
        {
            if (verbose)
                printf("INFO: runQuote Command Success\n");

        }
        else
        {
            printf("ERROR: runQuote Command Failed : %X\n", rc);
        }
    }
    else
    {
        printf("ERROR: Unable to send AcsPvmCommand - runQuote\n");
    }
    free (cmdBuffer);
    free (rspBuffer);
    cmdBuffer = NULL;
    rspBuffer = NULL;
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
    TPM_RC  rc = TPM_RC_SUCCESS;

    uint8_t *cmdBuffer = NULL;
    uint32_t cmdLength = 0;
    uint32_t rspLength = 0;
    uint8_t  *rspBuffer = NULL;                     /* freed @2 */

    uint8_t  logInstance = 0;
    uint32_t logHandle = 0;
    uint32_t logOffset = 0;
    uint32_t numBytes = 0;




    uint32_t logLength = 0;

    uint8_t moreData = FALSE;
    uint8_t logTruncated = FALSE;
    uint8_t showLogTruncatedMessage= FALSE;
    uint32_t responsePayLoadSize = AcsPvmMaxCommandResponseSize-sizeof(AcsPvmCommandResponseHeader);
    uint32_t totalLogLength = 0;
    logInstance = AcsLogTypeSRTM;

    rc = retrieveTPMLogSize(logInstance,&logHandle, (uint32_t *)&totalLogLength);

    if ( TPM_RC_SUCCESS == rc)
    {
        // we have the log buffer to write into the biosInputFilename
        // open the BIOS event log file
        FILE *outfile = NULL;
        size_t writeSize = 0;
        outfile = fopen(biosInputFilename,"wb");
        if (outfile == NULL)
        {
            printf("ERROR: Unable to open event log file '%s'\n", biosInputFilename);
            rc = TPM_RC_FAILURE;
        }

        cmdBuffer = malloc(AcsPvmMaxCommandRequestSize);
        cmdLength = sizeof(AcsPvmCommandRequestHeader);

        logLength = (totalLogLength < responsePayLoadSize) ? totalLogLength:responsePayLoadSize;

        while ( (logLength > 0) &&  (TPM_RC_SUCCESS == rc) )
        {
            numBytes = logLength;

            AcsPvmCommandRequest *cmdReq = (AcsPvmCommandRequest *) cmdBuffer;

            if (NULL == cmdReq)
            {
                printf("ERROR: Unable to allocate request buffer\n");
                rc = TPM_RC_FAILURE;
            }

            fillAcsPvmCommandHeader(AcsPvmCommandRetrieveTpmLog, cmdReq, cmdLength);

            BYTE* payload = (BYTE*)&cmdReq->payLoad;
            INT32 payloadSize = AcsPvmMaxCommandRequestSize - sizeof(AcsPvmCommandRequestHeader);
            uint16_t written = 0;

            if (TPM_RC_SUCCESS == rc)
            {
                rc = TSS_UINT8_Marshal(&logInstance, &written, &payload, &payloadSize);
            }

            if (TPM_RC_SUCCESS == rc)
            {
                rc = TSS_UINT32_Marshal(&logHandle, &written, &payload, &payloadSize);
            }

            if (TPM_RC_SUCCESS == rc)
            {
                rc = TSS_UINT32_Marshal(&logOffset, &written, &payload, &payloadSize);
            }

            if (TPM_RC_SUCCESS == rc)
            {
                rc = TSS_UINT32_Marshal(&numBytes, &written, &payload, &payloadSize);
            }

            if (TPM_RC_SUCCESS == rc)
            {
                cmdLength = cmdLength+written;
                cmdReq->header.length = htobe32(cmdLength);
            }

            if (TPM_RC_SUCCESS == rc)
            {
                rc = sendAcsPvmCommand(cmdBuffer, cmdLength, &rspBuffer, &rspLength);
            }

            /* parse response raw stream */
            if (rc == 0)
            {
                AcsPvmCommandResponse *cmdRes = (AcsPvmCommandResponse *) rspBuffer;

                INT32 payloadSize = be32toh(cmdRes->header.length) -
				    sizeof(AcsPvmCommandResponseHeader);

                BYTE* payload = (BYTE*)&cmdRes->payLoad;

                if (TPM_RC_SUCCESS == rc)
                {
                    rc = UINT8_Unmarshal(&moreData, &payload, &payloadSize);
                }

                if (TPM_RC_SUCCESS == rc)
                {
                    rc = UINT8_Unmarshal(&logTruncated, &payload, &payloadSize);
                    if ( (TPM_RC_SUCCESS == rc) && (logTruncated) && !showLogTruncatedMessage )
                    {
                        showLogTruncatedMessage = TRUE;
                        printf("INFO: retrieveTPMLog log Truncated\n");
                    }
                }

                if (TPM_RC_SUCCESS == rc)
                {
                    rc = UINT32_Unmarshal(&numBytes, &payload, &payloadSize);
                }

                if (TPM_RC_SUCCESS == rc && numBytes > 0)
                {
                    writeSize = fwrite(payload, 1, numBytes, outfile);
                    if (writeSize <= 0)
                    {
                        printf("ERROR: Unable to write to log file '%s' writeSize = %d "
			       "totalLogLength = 0x%08x\n",
                               biosInputFilename, (int)writeSize, totalLogLength);
                        rc = TPM_RC_FAILURE;
                    }
                    else if (writeSize < numBytes)
                    {
                        printf("ERROR: Unable to write all numBytes of data to log file '%s' "
			       "writeSize = %d totalLogLength = 0x%08x\n",
                               biosInputFilename, (int)writeSize, totalLogLength);
                        rc = TPM_RC_FAILURE;
                    }
                }
                logOffset += numBytes;
                logLength = ((totalLogLength - (int32_t)logOffset) >= responsePayLoadSize ) ?
                    responsePayLoadSize : (totalLogLength - (int32_t)logOffset);

                if (TPM_RC_SUCCESS == rc)
                {
                    if (verbose)
                        printf("INFO: retrieveTPMLog Command Success\n");


                }
                else
                {
		  printf("ERROR: retrieveTPMLog Command Failed : %X\n",rc);
                }
            }
            else
            {
                printf("ERROR: Unable to send AcsPvmCommand - retrieveTPMLog\n");
            }
        }

        if (outfile != NULL)
        {
            fclose(outfile);
        }
    }
    free (cmdBuffer);
    free (rspBuffer);
    cmdBuffer = NULL;
    rspBuffer = NULL;
    return rc;
}

TPM_RC retrieveTPMLogSize(uint8_t logInstance, uint32_t *logHandle, uint32_t * logLength)
{
    TPM_RC  rc = TPM_RC_SUCCESS;

    uint8_t *cmdBuffer = NULL;
    uint32_t cmdLength = 0;
    uint32_t rspLength = 0;
    uint8_t  *rspBuffer = NULL;                     /* freed @2 */

    cmdBuffer = malloc(AcsPvmMaxCommandRequestSize);
    cmdLength = sizeof(AcsPvmCommandRequestHeader);

    AcsPvmCommandRequest *cmdReq = (AcsPvmCommandRequest *) cmdBuffer;

    if (NULL == cmdReq)
    {
        printf("ERROR: Unable to allocate request buffer\n");
        rc = TPM_RC_FAILURE;
    }

    fillAcsPvmCommandHeader(AcsPvmCommandRetrieveTpmLogSize, cmdReq, cmdLength);

    BYTE* payload = (BYTE*)&cmdReq->payLoad;
    INT32 payloadSize = AcsPvmMaxCommandRequestSize - sizeof(AcsPvmCommandRequestHeader);
    uint16_t written = 0;

    if (TPM_RC_SUCCESS == rc)
    {
        rc = TSS_UINT8_Marshal(&logInstance, &written, &payload, &payloadSize);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        cmdLength = cmdLength+written;
        cmdReq->header.length = htobe32(cmdLength);
    }

    if (TPM_RC_SUCCESS == rc)
    {
        rc = sendAcsPvmCommand(cmdBuffer, cmdLength, &rspBuffer, &rspLength);
    }

    /* parse response raw stream */
    if (rc == 0)
    {
        AcsPvmCommandResponse *cmdRes = (AcsPvmCommandResponse *) rspBuffer;

        INT32 payloadSize = be32toh(cmdRes->header.length) - sizeof(AcsPvmCommandResponseHeader);

        BYTE* payload = (BYTE*)&cmdRes->payLoad;

        if (TPM_RC_SUCCESS == rc)
        {
            rc = UINT32_Unmarshal(logHandle, &payload, &payloadSize);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            rc = UINT32_Unmarshal(logLength, &payload, &payloadSize);
        }

        if (TPM_RC_SUCCESS == rc)
        {
            if (verbose)
                printf("INFO: retrieveTPMLogSize Command Success\n");

        }
        else
        {
	  printf("ERROR: retrieveTPMLogSize Command Failed : %X\n",rc);
        }
    }
    else
    {
        printf("ERROR: Unable to send AcsPvmCommand - retrieveTPMLogSize \n");
    }

    free (cmdBuffer);
    free (rspBuffer);
    cmdBuffer = NULL;
    rspBuffer = NULL;
    return rc;
}

uint32_t getBootTime(char *boottime,
                     size_t boottimeMax)
{
    // PowerVM returns the boottime as part of the quote, unfortunately
    // the acs client is looking for it during the earlier nonce generation step
    strncpy(boottime, "0000-00-00 00:00:00", boottimeMax);
    return 0;
}

TPM_RC getIntermediateCertificate(uint16_t *intermediateCertLength,
				  unsigned char **intermediateCert)
{
    //  PowerVM doesn't support or require intermediate certificates
    *intermediateCertLength = 0;
    return 0;
}
