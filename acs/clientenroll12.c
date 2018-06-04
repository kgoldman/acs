/********************************************************************************/
/*										*/
/*		TPM 1.2 Attestation - Client Side Enrollment			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientenroll12.c 1201 2018-05-04 19:38:41Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2018						*/
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

/*  The overall steps are:

    Create an attestation key.
    Send the attestation key and EK certificate to the server
    Activate credential on the challenge
    Send the challenge back to the server
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <json/json.h>

#include <tss2/tss.h>
#include <tss2/tpmstructures12.h>
#include <tss2/tssmarshal12.h>
#include <tss2/tssresponsecode.h>

#include "config.h"

#include "commonjson.h"
#include "commontss12.h"

#include "ekutils12.h"
#include "ekutils.h"

#include "commonutils.h"
#include "clientjson.h"
#include "clientjson12.h"
#include "clientsocket.h"

#include "commonerror.h"

#if 0
#include <tss2/tssutils.h>
#include <tss2/tssfile.h>
#include <tss2/tssprint.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include "commoncrypto.h"
#include "commontss.h"
#include "clientlocal.h"
#endif

/* local function prototypes */

static void printUsage(void);

static TPM_RC createEnrollmentData(char *tpmVendor,			/* freed by caller */
				   uint16_t *ekCertLength,
				   unsigned char **ekCertificate,
				   TPM_KEY12 *attestKey,
				   const char *srkPassword,
				   const char *ownerPassword,
				   TPMI_RH_NV_INDEX nvIndex);
static TPM_RC sendEnrollRequest(json_object **enrollResponseJson,
				const char *hostname,
				short port,
				const char *machineName,
				const char *tpmVendor,
				uint32_t ekCertLength,
				unsigned char *ekCertificate,
				TPM_KEY12 *attestKey);
static TPM_RC recoverAttestationKeyChallenge(TPM2B_DIGEST 	*certInfo,
					     TPM_KEY12 		*attestKey,
					     unsigned char 	*credentialBlobBin,
					     size_t 		credentialBlobBinSize,
					     const char 	*srkPassword,
					     const char 	*ownerPassword);
static TPM_RC processEnrollResponse(json_object **enrollCertResponseJson,
				    const char 	*hostname,
				    short	port,
				    const char 	*machineName,
				    TPM_KEY12 	*attestKey,
				    const char 	*srkPassword,
				    const char 	*ownerPassword,
				    json_object *enrollResponseJson);
static TPM_RC validateCertificate(const char *certificateFilename);
static TPM_RC processEnrollCertResponse(const char *certificateFilename,
					json_object *enrollCertResponseJson);

int verbose = 0;
int vverbose = 0;
#if 0
#ifdef TPM_ACS_PVM_REMOTE
char* g_sphost = NULL; /* Service processor hostname */
char* g_spport = NULL; /* Attestation port on service processor */
#endif

#endif
int main(int argc, char *argv[])
{
    int 		rc = 0;
    int			i;    /* argc iterator */
    /* command line argument defaults */
    TPM12_NV_INDEX 	ekCertIndex = TPM_NV_INDEX_EKCert;	/* default RSA */
    const char 		*hostname = "localhost";	/* default server */
#if 0
    const char 		*portString = NULL; 		/* server port */
#endif
    short 		port = 2323;			/* default server */
    const char          *machineName = NULL;		/* default use gethostname() */
    const char 		*ownerPassword = NULL;
    const char 		*srkPassword = NULL;  


    const char 		*certificateFilename = NULL;	/* default no AK certificate output */
    int			requestOnly = 0;		/* for server debug */
    const char 		*aikFilename = AK_FILENAME;
    char 		aikFullName[256];
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1"); /* default traces TSS errors */

#if 0
    /* get the socket port number as a string */
    portString = getenv("ACS_PORT");
    if (portString != NULL) {
        sscanf(portString , "%hu", &port);
    }
#endif
    /* parse command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		hostname = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-po") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i], "%hu", &port);
	    }
	    else {
		printf("ERROR: Missing parameter for -po\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ma") == 0) {
	    i++;
	    if (i < argc) {
            machineName = argv[i];
 	    }
	    else {
		printf("ERROR: Missing parameter for -ma\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-co") == 0) {
	    i++;
	    if (i < argc) {
		certificateFilename = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -co\n");
		printUsage();
	    }
	    
	}
	else if (strcmp(argv[i], "-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdo\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-pwds") == 0) {
	    i++;
	    if (i < argc) {
		srkPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwds\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ro") == 0) {
	    requestOnly = 1;
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = 1;
	}
	else if (strcmp(argv[i],"-vv") == 0) {
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");	/* trace entire TSS */
	    verbose = 1;
	    vverbose = 1;
	}
	else {
 	    printf("\nERROR: %s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    /* shared with client */
    rc = makeAkFilenames(NULL,
			 aikFullName,
			 sizeof(aikFullName),
			 NULL,			 
			 aikFilename,
			 machineName);
    if (rc != 0) {
	exit(1);
    }
    /* Create the enrollment data */
    char 		tpmVendor[5];
    uint16_t 		ekCertLength;
    unsigned char 	*ekCertificate = NULL;			/* freed @3 */	
    TPM_KEY12	 	attestKey;
    if (rc == 0) {
	if (vverbose) printf("INFO: createEnrollmentData\n");
	rc = createEnrollmentData(tpmVendor,
				  &ekCertLength, &ekCertificate,	/* freed @3 */
				  &attestKey, 
				  srkPassword, ownerPassword,
				  ekCertIndex);
    }
    /* send the enrollment data to the server */ 
    json_object *enrollResponseJson = NULL;
    if (rc == 0) {
	rc = sendEnrollRequest(&enrollResponseJson,		/* freed @1 */
			       hostname,
			       port,
			       machineName,
			       tpmVendor,
			       ekCertLength, ekCertificate,
			       &attestKey);
    }
    /* ActivateIdentity on the challenge. Send the challenge back to the server.  Process the AK
       certificate from the server. */
    json_object *enrollCertResponseJson = NULL;
    if ((rc == 0) && !requestOnly) {
	rc = processEnrollResponse(&enrollCertResponseJson,		/* freed @2 */
				   hostname,
				   port,
				   machineName,
				   &attestKey,
				   srkPassword,
				   ownerPassword,
				   enrollResponseJson);
    }
    if ((rc == 0) && !requestOnly && (certificateFilename != NULL)) {
	rc = processEnrollCertResponse(certificateFilename,
				       enrollCertResponseJson);
    }
    /* if enrollment is successful, save the key */
    if ((rc == 0) && !requestOnly) {
        rc = TSS_File_WriteStructure(&attestKey,
                                     (MarshalFunction_t)TSS_TPM_KEY12_Marshal,
                                     aikFullName);
    }
    JS_ObjectFree(enrollResponseJson);		/* @1 */
    JS_ObjectFree(enrollCertResponseJson);	/* @2 */
    free(ekCertificate);			/* @3 */
    return rc;
}

/* createEnrollmentData()

   FIXME for now assume takeownership already done

   reads the EK certificate
   
   creates an attestation key under that primary key.

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

static TPM_RC createEnrollmentData(char *tpmVendor,			/* freed by caller */
				   uint16_t *ekCertLength,
				   unsigned char **ekCertificate,	/* freed by caller */	
				   TPM_KEY12 *attestKey,
				   const char *srkPassword,
				   const char *ownerPassword,
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
	if (vverbose) printf("INFO: createEnrollmentData getTpmVendor12\n");
	rc = getTpmVendor12(tssContext, tpmVendor);	/* freed by caller */	
    }
    TPM_AUTHHANDLE sessionHandle = TPM_RH_NULL;
    /* create an OIAP session for general use */
    if (rc == 0) {
	if (vverbose) printf("INFO: createEnrollmentData startOIAP\n");
	rc = startOIAP(tssContext, &sessionHandle);
    }
    /* read the TPM EK certificate from TPM NV */
    if (rc == 0) {
	if (vverbose) printf("INFO: createEnrollmentData - get EK certificate\n");
	rc = getIndexContents12(tssContext,
				ekCertificate,		/* freed by caller */
				ekCertLength,		/* total size read */
				nvIndex,		/* RSA */
				ownerPassword,
				sessionHandle,		/* OIAP session */
				TPMA_SESSION_CONTINUESESSION);
    }
    /* Create the attestation signing key under the primary key */
    if (rc == 0) {
	if (vverbose) printf("INFO: createEnrollmentData - make AIK\n");
	rc = createAttestationKey12(tssContext,
				    attestKey, 
				    sessionHandle,	/* OIAP session */
				    srkPassword, ownerPassword);
	if (rc == 0) {	/* a successful makeidentity for some reason flushes both sessions */
	    sessionHandle = TPM_RH_NULL;
	}
    }
    if (sessionHandle != TPM_RH_NULL) {
	flushSpecific(tssContext,
		      sessionHandle, TPM_RT_AUTH);
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

/* sendEnrollRequest() sends a request of the form:

   {
   "command":"enrollrequest12",
   "hostname":"name",
   "tpmvendor":vendor",
   "ekcert":"hexascii",
   "akpub":"hexascii"
   }
*/

static TPM_RC sendEnrollRequest(json_object **enrollResponseJson,	/* freed by caller */
				const char *hostname,
				short port,
				const char *machineName,
				const char *tpmVendor,
				uint32_t ekCertLength,
				unsigned char *ekCertificate,		/* EK certificate */
				TPM_KEY12 *attestKey)			/* AK public key */
{
    TPM_RC 		rc = 0;
    uint32_t 		cmdLength;
    uint8_t 		*cmdBuffer = NULL;			/* freed @1 */
    uint32_t 		rspLength;
    uint8_t 		*rspBuffer = NULL;			/* freed @2 */
    char		*ekCertificateString = NULL;		/* freed @3 */
    char		*attestPubString = NULL;		/* freed @5 */
    uint16_t 		written = 0;
    uint8_t 		*buffer;
    uint32_t 		size;
    uint8_t		marshaled[4096];			/* large enough for marshaling */

    if (vverbose) printf("INFO: sendEnrollRequest\n");
    /* convert the EK certificate to string */
    if (rc == 0) {
	rc = Array_PrintMalloc(&ekCertificateString,		/* freed @3 */
			       ekCertificate,
			       ekCertLength);
    }
    /* marshal the TPM_KEY12 *attestKey as a TPM_PUBKEY */
    if (rc == 0) {
	written = 0;
	buffer = marshaled;
	size = sizeof(marshaled);
	rc = TSS_TPM_KEY12_PUBKEY_Marshal(attestKey, &written, &buffer, &size);
    }
    /* convert the Attestation public key to string */
    if (rc == 0) {
	rc = Array_PrintMalloc(&attestPubString,		/* freed @5 */
			       marshaled,
			       written);
    }
    /* construct the enrollment request command packet */
    if (rc == 0) {
	rc = JS_Cmd_EnrollRequest(&cmdLength,
				  (char **)&cmdBuffer,	/* freed @1 */
				  "enrollrequest12",
				  tpmVendor,
				  ekCertificateString,
				  attestPubString,
				  machineName);
    }
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,		/* freed @2 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream response to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(enrollResponseJson,	/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: sendEnrollRequest: response", *enrollResponseJson);
    }
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
    free(ekCertificateString);	/* @3 */
    free(attestPubString);	/* @5 */
    return rc;
}

/* processEnrollResponse() gets a server response of the form

   {
   "response":"enrollrequest",
   "credentialblob":"hexascii",
   }

   It sends a request of the form:
   {
   "command":"enrollcert",
   "hostname":"cainl.watson.ibm.com",
   "challenge":"hexascii",
   }
*/

static TPM_RC processEnrollResponse(json_object **enrollCertResponseJson,
				    const char *hostname,
				    short port,
				    const char *machineName,
				    TPM_KEY12 *attestKey,
				    const char *srkPassword,
				    const char *ownerPassword,
				    json_object *enrollResponseJson)
{
    TPM_RC 		rc = 0;
    uint32_t 		cmdLength;
    uint8_t 		*cmdBuffer = NULL;		/* freed @1 */
    uint32_t 		rspLength;
    uint8_t 		*rspBuffer = NULL;		/* freed @2 */

    if (vverbose) printf("INFO: processEnrollResponse: Entry\n");
    /* FIXME check for error response */
    const char *response = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&response, "response", enrollResponseJson);
    }
    /* get the credential blob */
    const char *credentialBlob = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&credentialBlob, "credentialblob", enrollResponseJson);
    }
    /* convert the credentialblob to binary */
    unsigned char 	*credentialBlobBin = NULL;
    size_t 		credentialBlobBinSize;
    if (rc == 0) {
	rc = Array_Scan(&credentialBlobBin,	/* output binary, freed @4 */
			&credentialBlobBinSize,
			credentialBlob);	/* input string */
    }    
    TPM2B_DIGEST certInfo;	/* the symmetric key */
    if (rc == 0) {
	rc = recoverAttestationKeyChallenge(&certInfo,	/* recovered challenge */
					    attestKey,
					    credentialBlobBin,
					    credentialBlobBinSize,
					    srkPassword,
					    ownerPassword);
    }
    /* convert the challenge to string */
    char *challengeString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&challengeString,		/* freed @6 */
			       certInfo.t.buffer,
			       certInfo.t.size);
    }
    if (rc == 0) {
	if (verbose) printf("INFO: processEnrollResponse: Recovered server challenge\n");
	if (vverbose) TSS_PrintAll("processEnrollResponse: Challenge:",
				   certInfo.t.buffer, certInfo.t.size);
    }
    /* construct the enrollment certificate command packet */
    /* converts the AK certificate to string */
    if (rc == 0) {
	rc = JS_Cmd_EnrollCert(&cmdLength,
			       (char **)&cmdBuffer,
			       challengeString,
			       machineName);
    }
    /* send the attestation certificate to the server */
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,	/* freed @2 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream response to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(enrollCertResponseJson,	/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: processEnrollResponse: response",
				    *enrollCertResponseJson);
    }
    /* cleanup */
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
    free(credentialBlobBin);	/* @4 */
    free(challengeString);	/* @6 */
    return rc;
}


/* processEnrollCertResponse() gets a server response of the form

   "response":"enrollcert",
   "akcert":"base64 encoded AK certificate"

   It stores the certificate in the file 'certificateFilename'.

   As a sanity check, the AK certificate is validated against the privacy CA certificate.

*/

static TPM_RC processEnrollCertResponse(const char *certificateFilename,
					json_object *enrollCertResponseJson)
{
    TPM_RC			rc = 0;
    if (vverbose) printf("INFO: processEnrollCertResponse: Entry\n");
    /* FIXME check for error response */
    const char *response = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&response, "response", enrollCertResponseJson);
    }
    /* get the AK certificate */
    const char *akCertPemString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&akCertPemString, "akcert", enrollCertResponseJson);
    }
    /* write the certificate to a file first, because openssl operates on PEM files */
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile((const uint8_t *)akCertPemString,
				      strlen(akCertPemString) +1,
				      certificateFilename);
    } 
    /* sanity check, validate the certificate against the privacy CA certificate */
    if (rc == 0) {
	rc = validateCertificate(certificateFilename);
    }
    return rc;
}

/* validateCertificate() sanity checks the AK certificate from the server against the privacy CA
   root certificate */

static TPM_RC validateCertificate(const char *certificateFilename)
{
    TPM_RC			rc = 0;

    X509 *akX509Certificate = NULL;
    /* convert the PEM certificate to x509 */
    if (rc == 0) {
	rc = convertPemToX509(&akX509Certificate,		/* freed &1 */
			      certificateFilename);
    }
    /*
      construct the privacy CA root certificate store
    */
    X509_STORE 		*caStore = NULL;	/* freed @2 */
    if (rc == 0) {
	caStore  = X509_STORE_new();		/* freed @2 */
	if (caStore == NULL) {
	    printf("validateCertificate: X509_store_new failed\n");  
	    rc = ACE_OUT_OF_MEMORY;
	}
    }
    /* read a root certificate from the file */
    FILE *caCertFile = NULL;			/* closed @3 */
    if (rc == 0) {
	caCertFile = fopen(PCA_CERT, "rb");	/* closed @3 */
	if (caCertFile == NULL) {
	    printf("validateCertificate: Error opening CA root certificate file %s\n", PCA_CERT);  
	    rc = ACE_FILE_OPEN;
	}
    }
    /* convert the root certificate from PEM to X509 */
    X509 	*caCert = NULL;
    if (rc == 0) {
	caCert = PEM_read_X509(caCertFile, NULL, NULL, NULL);	/* freed @4 */
	if (caCert == NULL) {
	    printf("validateCertificate: Error reading CA root certificate file %s\n",
		   PCA_CERT);  
	    rc = ACE_FILE_READ;
	} 
    }
    /* add the CA X509 certificate to the certificate store */
    if (rc == 0) {
	X509_STORE_add_cert(caStore, caCert);    
    }
    X509_STORE_CTX 		*verifyCtx = NULL;		/* freed @5 */
    /* create the certificate verify context */
    if (rc == 0) {
	verifyCtx = X509_STORE_CTX_new();
	if (verifyCtx == NULL) {
	    printf("ERROR: validateCertificate: X509_STORE_CTX_new failed\n");  
	    rc = ACE_OUT_OF_MEMORY;
	}
    }
    /* add the root CA certificate store and AK certificate to be verified to the verify context */
    if (rc == 0) {
	int irc = X509_STORE_CTX_init(verifyCtx, caStore, akX509Certificate, NULL);
	if (irc != 1) {
	    printf("ERROR: validateCertificate: "
		   "Error in X509_STORE_CTX_init initializing verify context\n");  
	    rc = ACE_OSSL_X509;
	}	    
    }
    /* walk the TPM AK certificate chain */
    if (rc == 0) {
	int irc = X509_verify_cert(verifyCtx);
	if (irc != 1) {
	    printf("ERROR: validateCertificate: "
		   "Error in X590_verify_cert verifying certificate\n");  
	    rc = ACE_INVALID_CERT;
	}
	else {
	    if (verbose) printf("INFO: validateCertificate: "
				"AK certificate verified against the PCA root\n");
	}
    }
    if (akX509Certificate != NULL) {
	X509_free(akX509Certificate);   /* @1 */
    }
    if (caStore != NULL) {
	X509_STORE_free(caStore);	/* @2 */
    }
    if (caCertFile != NULL) {
	fclose(caCertFile);		/* @3 */
    }
    if (caCert != NULL) {
	X509_free(caCert);	   	/* @4 */
    }
    if (verifyCtx != NULL) {
	X509_STORE_CTX_free(verifyCtx);	/* @5 */
    }
    return rc;
}

/* recoverAttestationKeyChallenge() recreates the primary EK, loads the attestation key pair, and
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

static TPM_RC recoverAttestationKeyChallenge(TPM2B_DIGEST 	*certInfo,
					     TPM_KEY12 		*attestKey,
					     unsigned char 	*credentialBlobBin,
					     size_t 		credentialBlobBinSize,
					     const char 	*srkPassword,
					     const char 	*ownerPassword)
{
    TPM_RC 			rc = 0;
    TPM_RC 			rc1;
    TSS_CONTEXT 		*tssContext = NULL;
    LoadKey2_In			loadKey2In;
    LoadKey2_Out		loadKey2Out;
    ActivateIdentity_In		activateIdentityIn;
    ActivateIdentity_Out	activateIdentityOut;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    TPM_AUTHHANDLE sessionHandle0 = TPM_RH_NULL;
    TPM_AUTHHANDLE sessionHandle1 = TPM_RH_NULL;
   /* create an OIAP session  */
    if (rc == 0) {
	if (vverbose) printf("INFO: recoverAttestationKeyChallenge startOIAP 0\n");
	rc = startOIAP(tssContext, &sessionHandle0);
    }
    /* create an OIAP session  */
    if (rc == 0) {
	if (vverbose) printf("INFO: recoverAttestationKeyChallenge startOIAP 1\n");
	rc = startOIAP(tssContext, &sessionHandle1);
    }
    /* load the attestation key saved in a file in the previous protocol step */
    if (rc == 0) {
	loadKey2In.parentHandle = TPM_RH_SRK;
	loadKey2In.inKey = *attestKey;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&loadKey2Out,
			 (COMMAND_PARAMETERS *)&loadKey2In,
			 NULL,
			 TPM_ORD_LoadKey2,
			 sessionHandle0, srkPassword, 1,
			 TPM_RH_NULL, NULL, 0);
	
	if (rc == 0) {
	    if (verbose) printf("INFO: recoverAttestationKeyChallenge: Attestation key %08x\n",
				loadKey2Out.inkeyHandle);
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: LoadKey2: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    } 
    if (rc == 0) {
	activateIdentityIn.idKeyHandle = loadKey2Out.inkeyHandle;
	activateIdentityIn.blobSize = credentialBlobBinSize;
	if (credentialBlobBinSize != sizeof(activateIdentityIn.blob)) {
	    printf("ERROR: recoverAttestationKeyChallenge: credentialBlobBinSize %u not %u\n",
		   (unsigned int)credentialBlobBinSize, (unsigned int)sizeof(activateIdentityIn.blob));
	    rc = ACE_BAD_BLOB;
	}
    }
    if (rc == 0) {
	memcpy(activateIdentityIn.blob, credentialBlobBin, credentialBlobBinSize);
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&activateIdentityOut,
			 (COMMAND_PARAMETERS *)&activateIdentityIn,
			 NULL,
			 TPM_ORD_ActivateIdentity,
			 sessionHandle0, NULL , 1,		/* AIK password */
			 sessionHandle1, ownerPassword, 1,	
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    if (vverbose) TSS_PrintAll("recoverAttestationKeyChallenge: Challenge:",
				       activateIdentityOut.symmetricKey.data,
				       activateIdentityOut.symmetricKey.size);
	    /* range check */
	    if (activateIdentityOut.symmetricKey.size > sizeof(certInfo->t.buffer)) {
		printf("ERROR: recoverAttestationKeyChallenge: symmetric key %u larger than %u\n",
		       activateIdentityOut.symmetricKey.size, (unsigned int)sizeof(sizeof(certInfo->t.buffer)));
		rc = ACE_BAD_BLOB;
	    }
	    certInfo->t.size = activateIdentityOut.symmetricKey.size;
	    memcpy(certInfo->t.buffer,
		   activateIdentityOut.symmetricKey.data, activateIdentityOut.symmetricKey.size);
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: ActivateIdentity: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }	
    /* flush the attestation key */
    if (verbose) printf("INFO: recoverAttestationKeyChallenge: Flush attestation key %08x\n",
			loadKey2Out.inkeyHandle);
    flushSpecific(tssContext, loadKey2Out.inkeyHandle, TPM_RT_KEY);
    if (verbose) printf("INFO: recoverAttestationKeyChallenge: Flush session %08x\n",
			sessionHandle0);
    flushSpecific(tssContext, sessionHandle0, TPM_RT_AUTH);
    if (verbose) printf("INFO: recoverAttestationKeyChallenge: Flush session %08x\n",
			sessionHandle1);
    flushSpecific(tssContext, sessionHandle1, TPM_RT_AUTH);
    {
	rc1 = TSS_Delete(tssContext);
	tssContext = NULL;
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("clientenroll12\n");
    printf("\n");
    printf("Provisions an attestation client with an attestation key.\n"
	   "Obtains a certificate from the attestation server.\n");
    printf("\n");
    printf("[-ho ACS server host name (default localhost)]\n");
    printf("[-po ACS server host port (default ACS_PORT or 2323)]\n");
    printf("[-ma Client machine name (default gethostname()]\n");
    printf("[-co AK certificate PEM output file name]\n");
    printf("[-pwds SRK password (default zeros)]\n");
    printf("[-pwdo owner password (default zeros)]\n");
    printf("[-ro Request only, for debug]\n");
    printf("\n");
    printf("Currently hard coded:\n");
    printf("\n");
    printf("\tAttestation key file name is ak{alg}priv_{machine}.bin/ak{alg}pub_{machine}.bin\n");
    printf("\tEndorsement hierarchy authorization assumes Empty Auth\n");
    printf("\n");
    exit(1);	
}
