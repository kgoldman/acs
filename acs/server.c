/********************************************************************************/
/*										*/
/*			TPM 2.0 Attestation - Server 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2022					*/
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
#include <time.h>
#include <ctype.h>

#include <arpa/inet.h>

#if 0
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#endif
#include <mysql/mysql.h>

#include <json/json.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>

#if TPM_TPM12
#include <ibmtss/Unmarshal12_fp.h>
#include <ibmtss/tssmarshal12.h>
#endif

#include "config.h"
#include "commonerror.h"
#include "serversocket.h"
#include "serverjson.h"
#include "commonjson.h"
#include "commonutils.h"
#include "commoncrypto.h"
#include "commontss.h"
#include "serversql.h"
#include "eventlib.h"
#include "imalib.h"
#include "cryptoutils.h"
#include "ekutils.h"

#ifdef ACS_BLOCKCHAIN
#include "serverbc.h"
#endif

/* local function prototypes */

static uint32_t processRequest(unsigned char **rspBuffer,
			       uint32_t *rspLength,
			       unsigned char *cmdBuffer,
			       uint32_t cmdLength,
			       const char *listFilename);
static uint32_t processSendError(unsigned char **rspBuffer,
				 uint32_t *rspLength,
				 uint32_t errorCode);
static uint32_t processNonce(unsigned char **rspBuffer,
			     uint32_t *rspLength,
			     json_object *cmdJson);
static uint32_t processQuote(unsigned char **rspBuffer,
			     uint32_t *rspLength,
			     json_object *cmdJson,
			     unsigned char *cmdBuffer);
static void makePcrSelect20(TPML_PCR_SELECTION *pcrSelection);
static void getBiosPCRselect(uint8_t *sizeOfSelect,
			     uint8_t pcrSelect[],
			     int tpm20);
static uint32_t makePcrStream20(unsigned char 	*pcrBinStream,
				size_t 		*pcrBinStreamSize,
				unsigned char 	**pcrsSha256Bin,
				TPML_PCR_SELECTION *pcrSelection);
static uint32_t initializePCRs(MYSQL *mysql,
			       const char *hostname);
static uint32_t copyPreviousPCRs(const char *boottime,
				 MYSQL *mysql,
				 const char *hostname);
static uint32_t checkBiosPCRsMatch(unsigned int *previousBiosPcrs,
				   unsigned int *biosPcrsMMatch,
				   const char	*quotePcrsString[],
				   int 		tpm20,
				   const char 	*attestLogId,
				   MYSQL	*mysql,
				   const char *hostname);
static uint32_t processBiosEntries20Pass1(unsigned int *eventNum,
					  size_t quotePcrsSha256BinLength[],
					  uint8_t *quotePcrsSha256Bin[],
					  const char *previousPcrs[],
					  json_object *cmdJson);
static uint32_t processBiosEntries20Pass2(const char *hostname,
					  const char *timestamp,
					  json_object *cmdJson,
					  MYSQL *mysql);
static uint32_t processImaEntries20Pass1(unsigned int *logVerified,
					 unsigned int *nextImaEventNum,
					 unsigned int firstImaEventNum,
					 size_t quotePcrsSha256BinLength[],
					 uint8_t *quotePcrsSha256Bin[],
					 const char *previousPcrs[],
					 TPMS_ATTEST *tpmsAttest,
					 json_object *cmdJson);
static uint32_t verifyQuoteSignature(unsigned int 	*quoteVerified,
				     unsigned char 	*quotedBin,
				     size_t 		quotedBinSize,
				     const char 	*akCertificatePem,
				     TPMT_SIGNATURE 	*tpmtSignature);
static uint32_t verifyQuoteSignatureRSA(unsigned int 	*quoteVerified,
					int 		sha256,
					TPMT_HA 	*digest,
					X509 		*x509,
					TPMT_SIGNATURE 	*tpmtSignature);
static uint32_t verifyQuoteSignatureECC(unsigned int 	*quoteVerified,	
					TPMT_HA 	*digest,
					X509 		*x509,
					TPMT_SIGNATURE 	*tpmtSignature);
static uint32_t verifyQuoteNonce(unsigned int 	*quoteVerified,
				 const char 	*nonceServerString,
				 TPMS_ATTEST 	*tpmsAttest);
static uint32_t processQuoteResults(json_object 	*cmdJson,
				    unsigned int 	quoteVerified,
				    const char 		*attestLogId,
				    MYSQL 		*mysql);
uint32_t processBiosLogResults(unsigned int 	logVerified,
			       unsigned int 	eventNum,
			       const char 	*attestLogId,
			       MYSQL 		*mysql);
uint32_t processImaLogResults(unsigned int 	logVerified,
			      unsigned int 	nextImaEventNum,
			      const char 	*attestLogId,
			      MYSQL 		*mysql);
static unsigned updateImaState(unsigned int 	nextImaEventNum,
			       char		*imaPcrString,
			       const char 	*machineId,
			       MYSQL 		*mysql);

static uint32_t processQuotePCRs(char 		*quotePcrsString[],
				 const char 	*attestLogId,
				 MYSQL 		*mysql);
static uint32_t processQuoteWhiteList(char 		*quotePcrsString[],
				      const char 	*hostname,
				      const char 	*attestLogId,
				      MYSQL 		*mysql);
static uint32_t pcrBinToString(char *pcrsString[],
			       TPMI_ALG_HASH halg,
			       uint8_t **pcrsBin);
static uint32_t processImaEntriesPass2(int *imasigver,
				       const char *machineName,
				       const char *boottime,
				       const char *timestamp,
				       json_object *cmdJson,
				       unsigned int firstEventNum,
				       unsigned int lastEventNum,
				       const char *attestLogId,
				       MYSQL *mysql);
static uint32_t processEnrollRequest(unsigned char **rspBuffer,
				     uint32_t *rspLength,
				     json_object *cmdJson,
				     const char *listFilename);
static uint32_t validateEkCertificate(TPMT_PUBLIC *ekPub,
				      X509 **ekX509Certificate,
				      const char *ekCertString,
				      const char *listFilename);
static uint32_t validateAttestationKey(TPMT_PUBLIC *attestPub,
				       const char *attestPubString);
static uint32_t generateEnrollmentChallenge(TPM2B_DIGEST *challenge,
					    char **challengeString);
static uint32_t generateAttestationCert(char **akx509CertString,
					char **akCertPemString,
					uint8_t **attestCertBin,
					uint32_t *attestCertBinLen,
					const char *hostname,
					TPMT_PUBLIC *attestPub);
static uint32_t generateCredentialBlob(char **credentialBlobString,
				       TPM2B_ID_OBJECT *credentialBlob,
				       char **secretString,
				       TPM2B_ENCRYPTED_SECRET *secret,
				       TPMT_PUBLIC *attestPub,
				       TPMT_PUBLIC *ekPub,
				       TPM2B_DIGEST *credential);
static uint32_t processEnrollCert(unsigned char **rspBuffer,
				  uint32_t *rspLength,
				  json_object *cmdJson);
static uint32_t makecredential(TSS_CONTEXT *tssContext,
			       TPM2B_ID_OBJECT *credentialBlob,
			       TPM2B_ENCRYPTED_SECRET *secret,
			       TPM_HANDLE handle,
			       TPM2B_DIGEST *credential,
			       TPM2B_NAME *objectName);

static void getTimeStamp(char *timestamp,
			 size_t size);
static uint32_t getPubKeyFingerprint(uint8_t *x509Fingerprint,
				     size_t fingerprintSize,
				     X509 *x509);
uint32_t verifyImaTemplateData(uint32_t *badEvent, 
			       ImaTemplateData *imaTemplateData,
			       int 	littleEndian,
			       ImaEvent *imaEvent,
			       int eventNum);
uint32_t verifyImaSigPresent(uint32_t *noSig,
			     ImaTemplateData *imaTemplateData,
			     int eventNum);
uint32_t getImaPublicKeyIndex(uint32_t *noKey,
			      unsigned int *imaKeyNumber,
			      ImaTemplateData *imaTemplateData,
			      int eventNum);
uint32_t verifyImaSignature(uint32_t *badSig,
			    const ImaTemplateData *imaTemplateData,
			    EVP_PKEY *evpPkey,
			    int eventNum);

/* Support for TPM 1.2 */

#ifdef TPM_TPM12
static uint32_t processQuote12(unsigned char **rspBuffer,
			       uint32_t *rspLength,
			       json_object *cmdJson,
			       unsigned char *cmdBuffer);
static uint32_t processQuoteResults12(json_object 	*cmdJson,
				      unsigned int 	quoteVerified,
				      const char 	*attestLogId,
				      MYSQL 		*mysql);
static uint32_t verifyQuoteSignature12(unsigned int 	*quoteVerified,	
				       const char 	*nonceServerString,
				       unsigned char 	*pcrDataBin,
				       size_t 		pcrDataBinSize,
				       unsigned char 	*versionInfoBin,
				       size_t 		versionInfoBinSize,
				       const char 	*akCertificatePem,
				       unsigned char 	*signatureBin,
				       size_t 		signatureBinSize);
static uint32_t processBiosEntries12Pass1(unsigned int *eventNum,
					  size_t quotePcrsSha1BinLength[],
					  uint8_t *quotePcrsSha1Bin[],
					  const char *previousPcrs[],
					  json_object *cmdJson);
static uint32_t processBiosEntries12Pass2(const char *hostname,
					  const char *timestamp,
					  json_object *cmdJson,
					  MYSQL *mysql);
static uint32_t processImaEntries12Pass1(unsigned int *logVerified,
					 unsigned int *nextImaEventNum,
					 unsigned int firstImaEventNum,
					 size_t quotePcrsSha1BinLength[],
					 uint8_t *quotePcrsSha1Bin[],
					 const char *previousPcrs[],
					 TPM_PCR_INFO_SHORT *pcrInfoShort,
					 json_object *cmdJson);
static uint32_t processEnrollRequest12(unsigned char **rspBuffer,
				       uint32_t *rspLength,
				       json_object *cmdJson,
				       const char *listFilename);
static uint32_t validateAttestationKey12(TPMT_PUBLIC *attestPub20,
					 TPM_PUBKEY *attestPub12,
					 const char *attestPubString);
static uint32_t generateCredentialBlob12(uint8_t *encBlob,
					 size_t encBlobSize,
					 char **credentialBlobString,
					 TPM_PUBKEY *attestPub,
					 TPMT_PUBLIC *ekPub,
					 TPM2B_DIGEST *challenge);
static void makePcrSelect12(uint32_t *valueSize,
			    TPM_PCR_SELECTION *pcrSelection);
static uint32_t makePcrStream12(unsigned char 	*pcrBinStream,
				uint16_t	*pcrBinStreamSize,
				unsigned char 	**pcrsSha1Bin);
static int isPrintableString(const uint8_t *string);
#endif

static void printUsage(void);

int vverbose = 0;
int verbose = 0;

#define IMA_KEYS_MAX 100

/* IMA signature verification certificates, initialized at startup */
unsigned int 	imaKeyCount = 0;
const char 	*imaCertFilename[IMA_KEYS_MAX];
uint8_t 	imaFingerprint[IMA_KEYS_MAX][4];
EVP_PKEY	*imaRsaPkey[IMA_KEYS_MAX];

int main(int argc, char *argv[])
{
    uint32_t  	rc = 0;
    int		i;    		/* argc iterator */
    const char 	*listFilename = NULL;
    const char 	*imaCertFilename[IMA_KEYS_MAX];
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    /* parse command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-root") == 0) {
	    i++;
	    if (i < argc) {
		listFilename = argv[i];
	    }
	    else {
		printf("-root option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-imacert") == 0) {
	    i++;
	    if (i < argc) {
		if (imaKeyCount < IMA_KEYS_MAX) {
		    imaCertFilename[imaKeyCount] = argv[i];
		    imaKeyCount++;
		}
		else {
		    printf("-imacert exceeds max %u\n", IMA_KEYS_MAX); 
		    printUsage();
		}
	    }
	    else {
		printf("-imacert option needs a value\n");
		printUsage();
	    }
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
    if (imaKeyCount == 0) {
	printf("\nERROR: -imacert is required at least once\n");
	printUsage();
    }
    if (listFilename == NULL) {
	printf("\nERROR: -root is required\n");
	printUsage();
    }
    time_t  start_time = time(NULL);
    printf("main: Starting server at %s", ctime(&start_time));
    /* initialize the IMA public key store with the IMA certificates and the fingerprints */
    unsigned int imaKeyNumber;
    for (imaKeyNumber = 0 ; (rc == 0) && (imaKeyNumber < imaKeyCount) ; imaKeyNumber++) {
	X509 *imaX509 = NULL;			/* signature verification certificate */
	if (verbose) printf("INFO: main: Processing IMA cert %u at file %s\n",
			    imaKeyNumber, imaCertFilename[imaKeyNumber]);
	/* extract openssl format IMA public key from the IMA certificate */
	if (rc == 0) {
	    rc = getPubkeyFromDerCertFile3(&imaRsaPkey[imaKeyNumber],	/* freed FIXME */
					   &imaX509,			/* freed @2 */
					   imaCertFilename[imaKeyNumber]);
	}
	/* get the fingerprint, the X509 certificate Subject Key Identifier last 4 bytes  for IMA */
	if (rc == 0) {
	    rc = getPubKeyFingerprint(imaFingerprint[imaKeyNumber],
				      sizeof(imaFingerprint[imaKeyNumber]), imaX509);
	}
	if (imaX509 != NULL) {
	    X509_free(imaX509);		/* @2 */
	}
    }
    for (imaKeyNumber = 0 ; vverbose && (rc == 0) && (imaKeyNumber < imaKeyCount) ; imaKeyNumber++) {
	printf("main: IMA certificate %u %s ", imaKeyNumber, imaCertFilename[imaKeyNumber]);
	Array_Print(NULL, "fingerprint", TRUE,
		    imaFingerprint[imaKeyNumber], sizeof(imaFingerprint[imaKeyNumber]));
    }
    int 	sock_fd;	/* server socket */
    if (rc == 0) {
	rc = Socket_Init(&sock_fd);
    }
    /* test the database connection */
    if (rc == 0) {
	MYSQL *mysql = NULL;
	rc = SQ_Connect(&mysql);	/* closed @1 */	
	SQ_Close(mysql);		/* @1 */
    }
    if (rc != 0) {	
	return rc;			/* server cannot start, fatal error */
    }
    /* server main loop */
    while (1) {
	int connection_fd = -1;					/* disconnect @3 */
	unsigned char *cmdBuffer = NULL; 		  	/* command stream */
	uint32_t cmdLength;
	unsigned char *rspBuffer = NULL; 		  	/* command stream */
	uint32_t rspLength;

	if (rc == 0) {
	    rc = Socket_Connect(&connection_fd, sock_fd);	/* disconnect @3 */
	}
	if (rc == 0) {
	    rc = Socket_Read(connection_fd,        	/* read/write file descriptor */
			     &cmdBuffer,   		/* output: command stream, freed @1 */
			     &cmdLength);		/* output: command stream length */
	}	
	/* process client request */
	if (rc == 0) {
	    if (verbose) {
		char timestamp[80];
		getTimeStamp(timestamp, sizeof(timestamp));
		printf("INFO: main: json command at %s\n%s\n", timestamp, cmdBuffer);
	    }
	}
	if (rc == 0) {
	    rc = processRequest(&rspBuffer,		/* freed @2 */
				&rspLength,
				cmdBuffer,   		/* input: command stream */
				cmdLength,		/* output: command stream length */
				listFilename);
	}
	if (rc == 0) {
	    rc = Socket_Write(connection_fd,       /* read/write file descriptor */
			      rspBuffer,
			      rspLength);
	}
	/* only fatal server errors should abort the server */
	if (!((rc >= ASE_ERROR_FIRST) && (rc <= ASE_ERROR_LAST))) {
	    rc = 0;	/* client errors should not */
	}
	Socket_Disconnect(&connection_fd);	/* @3 */
	free(cmdBuffer);			/* @1 */
	cmdBuffer = NULL;
	free(rspBuffer);			/* @2 */
	rspBuffer = NULL;
    }
    return rc;
}

/* processRequest() is the entry point for all client requests.

   The client command is in cmdBuffer, and the client response is put in the allocated rspBuffer.

   An failure return is fatal.
*/

static uint32_t processRequest(unsigned char **rspBuffer,	/* freed by caller */
			       uint32_t *rspLength,
			       unsigned char *cmdBuffer,
			       uint32_t cmdLength,
			       const char *listFilename)
{
    uint32_t  rc = 0;
    json_object *cmdJson = NULL;
    const char *commandString;

    /* parse the json command and extract the command string */
    if (rc == 0) {
	rc = JS_Cmd_GetCommand(&commandString,
			       &cmdJson,		/* freed @1 */
			       (char *)cmdBuffer,
			       cmdLength);
    }
    /* dispatch based on the command.  These functions are required to put something into the
       response buffer. */
    if (rc == 0) {
	/* nonce */
	if ((strcmp(commandString, "nonce") == 0) || 
	    (strcmp(commandString, "nonce12") == 0)) {
	    if (vverbose) printf("processRequest: processing nonce\n");
	    rc = processNonce(rspBuffer,		/* freed by caller */
			      rspLength,
			      cmdJson);
	}
	/* quote */
	else if (strcmp(commandString, "quote") == 0) {
	    if (vverbose) printf("processRequest: processing quote\n");
	    rc = processQuote(rspBuffer,		/* freed by caller */
			      rspLength,
			      cmdJson,
			      cmdBuffer);
	}
#ifdef TPM_TPM12
	/* TPM 1.2 quote2 */
	else if (strcmp(commandString, "quote12") == 0) {
	    if (vverbose) printf("processRequest: processing quote2\n");
	    rc = processQuote12(rspBuffer,		/* freed by caller */
				rspLength,
				cmdJson,
				cmdBuffer);
	}
#endif
	/* enrollment request */
	else if (strcmp(commandString, "enrollrequest") == 0) {
	    if (vverbose) printf("processRequest: processing enrollrequest\n");
	    rc = processEnrollRequest(rspBuffer,	/* freed by caller */
				      rspLength,
				      cmdJson,
				      listFilename);
	}
#ifdef TPM_TPM12
	/* enrollment request */
	else if (strcmp(commandString, "enrollrequest12") == 0) {
	    if (vverbose) printf("processRequest: processing enrollrequest12\n");
	    rc = processEnrollRequest12(rspBuffer,	/* freed by caller */
					rspLength,
					cmdJson,
					listFilename);
	}
#endif
	/* enrollment certificate */
	else if (strcmp(commandString, "enrollcert") == 0) {
	    if (vverbose) printf("processRequest: processing enrollcert\n");
	    rc = processEnrollCert(rspBuffer,		/* freed by caller */
				   rspLength,
				   cmdJson);
	}
	/* if the client sent an unknown command, send this response These is a client errors that
	   should not abort the server.*/
	else {
	    printf("ERROR: processRequest: command %s unknown \n", commandString);
	    rc = processSendError(rspBuffer,		/* freed by caller */
				  rspLength,
				  ACE_UNKNOWN_CMD);

	}
	/* if the client command processor failed to construct the response packet, try constructing
	   the response json explicitly. These are likely to be client errors that should not abort
	   the server. */
	if (rc != 0) {
	    printf("ERROR: processRequest: server could not construct response json\n");
	    free(*rspBuffer);
	    *rspBuffer = NULL;
	    rc = processSendError(rspBuffer,		/* freed by caller */
				  rspLength,
				  ASE_NO_RESPONSE);
	}
    }
    /* json command parse error.  These are client errors that should not abort the server. */
    else {
	printf("ERROR: processRequest: server could not parse command json\n");
	rc = processSendError(rspBuffer,		/* freed by caller */
			      rspLength,
			      ACE_BAD_JSON);
    }
    JS_ObjectFree(cmdJson);	/* @1 */
    return rc;	
}

/* processSendError() sends response json of the form

   {
   "error":"errorCode"
   }

   This is a fatal server error.

*/

static uint32_t processSendError(unsigned char **rspBuffer,	/* freed by caller */
				 uint32_t *rspLength,
				 uint32_t errorCode)
{
    uint32_t  	rc = 0;
    
    /* create the error return json */
    json_object *response = NULL;
    rc = JS_ObjectNew(&response);			/* freed @1 */
    if (rc == 0) {
	rc = JS_Rsp_AddError(response, errorCode);
    }
    if (rc == 0) {	
	rc = JS_ObjectSerialize(rspLength,
				(char **)rspBuffer,	/* freed by caller */
				response);		/* @1 */
    }
    return rc;
}

/* processNonce() generates a 32 byte binary nonce, creates the client response.

   The client command is of the form:

   {
   "command":"nonce",

   or
   
   "command":"nonce12",
   
   "hostname":"cainl.watson.ibm.com",
   "userid":"kgold"
   "boottime":"2019-12-02 10:12:57"
   }

   ~~

   It updates the machine DB entry with the boottime, zero IMA events, and the initial all zero IMA
   PCR.
   
   It creates an attestlog DB entry for this client attestation, with:

   userid - the client user name
   hostname - the client machine name
   timestamp - server time
   nonce - generated on the server
   pcrselect - depending on TPM 2.0 or TPM 1.2, BIOS and IMA PCRs
   boottime - client reported boot time

   ~~

   The client response is of the form:

   {
   "response":"nonce",
   "nonce":"9c0fe9df6b609dd753530ecda1bfb1e6a7d32460ddb8e36c35f028281b7d8c5d",
   "pcrselect":"00000002000b03ff0400000403000000"

   for new logs
   
   "biosentry":"0",
   "imaentry":"0"

   for incremental IMA log

   "biosentry":"-1",
   "imaentry":"1083"

   }
*/

static uint32_t processNonce(unsigned char **rspBuffer,		/* freed by caller */
			     uint32_t *rspLength,
			     json_object *cmdJson)
{
    uint32_t  	rc = 0;
    int		irc = 0;

    if (verbose) printf("INFO: processNonce: Entry\n");
    /* get the command, nonce for TPM 2.0 and nonce12 for TPM 1.2 */
    const char *commandString;
    if (rc == 0) {
	rc = JS_ObjectGetString(&commandString, "command", ACS_JSON_COMMAND_MAX, cmdJson);
    }
    /* get the client machine name from the command */
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    /* get the client user name from the command - userid in ACS terms */
    const char *userid = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&userid, "userid", ACS_JSON_USERID_MAX, cmdJson);
    }
    /* Get the client boottime. Can be null on the first boot. */
    const char 	*clientBoottime = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&clientBoottime, "boottime", ACS_JSON_TIME_MAX, cmdJson);
    }
    /* connect to the db */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @1 */	
    }
    /* get the DB information for this machine, verify that machine is enrolled */
    MYSQL_RES 		*machineResult = NULL;
    char 		*machineId = NULL;	/* row being updated */
    const char 		*akCertificatePem = NULL;
    const char 		*boottime = NULL;
    unsigned int 	imaevents;		/* next event to be processed */
    if (rc == 0) {
	rc = SQ_GetMachineEntry(&machineId,		/* machineId freed @5 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				&boottime,		/* boottime */
				&imaevents,		/* imaevents */
				NULL,			/* imapcr */
				&machineResult,		/* freed @2 */
				mysql,
				hostname);
	if (rc != 0) {
	    printf("ERROR: processNonce: row for hostname %s does not exist in machine table\n",
		   hostname);
	}
	else if (akCertificatePem == NULL) {
	    printf("ERROR: processNonce: "
		   "row for hostname %s has invalid certificate in machine table\n",
		   hostname);  
	    rc = ACE_INVALID_CERT;
	}
    }
    int newBoot;
    if (rc == 0) {
	if (boottime == NULL) {
	    newBoot = TRUE;
	}
	else {
	    newBoot = strcmp(boottime, clientBoottime);	/* is this a new client boot cycle */
	}
	if (vverbose) printf("processNonce: new boot boolean %u\n", (newBoot != 0));
    }
    /* new boottime to machines */
    char 	query[QUERY_LENGTH_MAX];
    if ((rc == 0) && (machineId != NULL) && newBoot) {
	if (verbose) printf("INFO: processNonce: store boottime %s\n", clientBoottime);
	imaevents = 0;		/* new boot, next event to be processed is 0 */
	if (rc == 0) {
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "update machines set boottime = '%s', "
			       "imaevents = '%u', imapcr = '%s' "
			       "where id = '%s'",
			       clientBoottime,
			       imaevents,
			       "0000000000000000000000000000000000000000000000000000000000000000",
			       machineId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processNonce: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    /* generate binary nonce for the client attestation */
    unsigned char nonceBinary[SHA256_DIGEST_SIZE];
    if (rc == 0) {
	irc = RAND_bytes(nonceBinary, SHA256_DIGEST_SIZE);
	if (irc != 1) {
	    printf("ERROR: processNonce: RAND_bytes failed\n");
	    rc = ASE_OSSL_RAND;
	}
    }
    /* convert nonceBinary to text for the response */
    char *nonceString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&nonceString,		/* freed @3 */
			       nonceBinary, SHA256_DIGEST_SIZE);
    }
    /* construct a server timestamp */
    char timestamp[80];
    if (rc == 0) {
	getTimeStamp(timestamp, sizeof(timestamp));
    }
    char *pcrSelectionString = NULL;
    if (rc == 0) {
#ifdef TPM_TPM12
	if (strcmp(commandString, "nonce") == 0) {		/* TPM 2.0 */
#endif
	    TPML_PCR_SELECTION	pcrSelection;
	    /* pcrselect, two banks, PCR0-7 in SHA-256 bank, PCR 10 (IMA PCR) in SHA-256 bank */
	    makePcrSelect20(&pcrSelection);
	    rc = Structure_Print(&pcrSelectionString,		/* freed @4 */
				 &pcrSelection,
				 (MarshalFunction_t)TSS_TPML_PCR_SELECTION_Marshalu);
#ifdef TPM_TPM12
	}
	else {		/* TPM 1.2 */
	    uint32_t valueSize;
	    TPM_PCR_SELECTION pcrSelection;
	    makePcrSelect12(& valueSize, &pcrSelection);
	    rc = Structure_Print(&pcrSelectionString,		/* freed @4 */
				 &pcrSelection,
				 (MarshalFunction_t)TSS_TPM_PCR_SELECTION_Marshalu);
	}
#endif
    }
    /* copy the nonce to the new db entry for later compare */
    /* create a new db entry, quoteverified is NULL, indicating nonce has not been used */
    if (rc == 0) {
	int irc = snprintf(query, QUERY_LENGTH_MAX,
		"insert into attestlog "
			   "(userid, hostname, timestamp, nonce, pcrselect, boottime) "
			   "values ('%s','%s','%s','%s','%s','%s')",
			   userid, hostname, timestamp, nonceString,
			   pcrSelectionString, clientBoottime);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processNonce: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    /* if new boot, initialize the PCRs */
    if (rc == 0) {
	if (newBoot) {
	    /* if new boot, initialize the attestlog PCRs to all zero */
	    rc = initializePCRs(mysql, hostname);
	}
	else {
	    /* if incremental, copy previous PCRs to attestlog PCRs */
	    rc = copyPreviousPCRs(clientBoottime, mysql, hostname);
	}
    }
    /* create the nonce return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);	/* freed @6 */
    if (rc1 == 0) {
	char eventsString[16];
	if (rc == 0) {
	    json_object_object_add(response, "response",
				   json_object_new_string("nonce"));
	    json_object_object_add(response, "nonce",
				   json_object_new_string(nonceString));
	    json_object_object_add(response, "pcrselect",
				   json_object_new_string(pcrSelectionString));
	    /* if new boot cycle, request full logs */
	    unsigned int biosEvents;
	    if (newBoot) {
		biosEvents = 0;		/* new boot, get pre-OS events */
	    }
	    else {
		biosEvents = -1;	/* incremental, pre-OS events not required */	
	    }
	    if (rc == 0) {
		sprintf(eventsString, "%d", biosEvents);
		json_object_object_add(response, "biosentry",
				       json_object_new_string(eventsString));
	    }
	    if (rc == 0) {
		sprintf(eventsString, "%d", imaevents);
		json_object_object_add(response, "imaentry",
				       json_object_new_string(eventsString));
	    }
	}
	/* processing error */
	else {
	    rc1 = JS_Rsp_AddError(response, rc);
	}
	if (rc1 == 0) {	
	    rc = JS_ObjectSerialize(rspLength,
				    (char **)rspBuffer,	/* freed by caller */
				    response);		/* @6 */
	}
    }
    /* could not construct response */
    else {
	rc = rc1;
    }
    SQ_Close(mysql);			/* @1 */
    SQ_FreeResult(machineResult);	/* @2 */
    free(nonceString);			/* @3 */
    free(pcrSelectionString);		/* @4 */
    free(machineId);			/* @5 */
    return rc;
}

/* processQuote() processes the client quote and creates the client response.

   The client command is:

   {
   "command":"quote",
   "hostname":"cainl.watson.ibm.com",
   "quoted":"hexascii",
   "signature":"hexascii",
   "event1":"000000010000000500...",
   "imaevent0":"0000000aa97937766682b ...",  
   }

   The server response is this if BIOS PCRs match:
     
   {
   "response":"quote"
   }
     
   ~~

   Verifies the quote signature
   Verifies the nonce
   Walks the BIOS event log and reconstructs the PCRs (pass 1)
   Walks the IMA event log until the PCRs match the quote (pass 1)
   Checks the PCR white list if available
   Validates the IMA event (pass 2)
   
   
   Initializes the machines PCR white list
   Initializes the machines imaevents, imapcr, boottime

   Updates the attestlog with

   - raw quote json, excluding the event logs
   - quote signature verified
   - event logs verified, match the quote
   - the BIOS events and IMA event processed
   - reconstructed PCRs
   - validation of the PCR white list
   - whether the BIOS PCRs changed since the last attestation

   Updates the machines DB with

   - next IMA event to be processed in an incremental attestation
   - IMA PCR to be used in an incremental attestation
   - PCR white list if the first attestation

   Adds a bioslog entry with the BIOS events (pass 2)
   Adds an imalog entry with the IMA events (pass 2)

*/

static uint32_t processQuote(unsigned char **rspBuffer,		/* freed by caller */
			     uint32_t *rspLength,
			     json_object *cmdJson,
			     unsigned char *cmdBuffer)
{
    uint32_t  		rc = 0;	
    unsigned char 	*tmpptr;	/* so unmarshal pointers don't move */
    uint32_t		tmpsize;
    
    /* from client */
    const char 		*hostname = NULL;
    const char 		*quoted = NULL;		/* quote in hexascii */
    unsigned char 	*quotedBin = NULL;	/* quote in binary */
    size_t 		quotedBinSize;
    const char 		*signature = NULL;
    unsigned char 	*signatureBin = NULL;
    size_t 		signatureBinSize;
    
    /* status flags */
    unsigned int 	quoteVerified = TRUE;	/* TRUE if quote signature verified AND nonce
						   matches */
    unsigned int 	logVerified = FALSE;	/* PCR digest matches event logs */

    unsigned int 	biosPcrsMatch = FALSE; 	/* TRUE if previous valid quote and PCRs did not
						   change */
    unsigned int	previousBiosPcrs = FALSE;	/* TRUE is there was a previous valid
							   quote */

    cmdBuffer = cmdBuffer;
    if (vverbose) printf("INFO: processQuote: Entry\n");
    /*
      Get data from client command json
    */
    /* Get the client hostname.  Do this first since this DB column should be valid. */
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    /* Get the client quoted data */
    if (rc == 0) {
	rc = JS_ObjectGetString(&quoted, "quoted", ACS_JSON_QUOTED_MAX, cmdJson);
    }
    /* convert the quoted to binary */
    if (rc == 0) {
	rc = Array_Scan(&quotedBin ,	/* output binary, freed @1 */
			&quotedBinSize,
			quoted);	/* input string */
    }    
    /* Get the client quote signature */
    if (rc == 0) {
	rc = JS_ObjectGetString(&signature, "signature", ACS_JSON_SIGNATURE_MAX, cmdJson);
    }
    /* convert the signature to binary marshaled TPMT_SIGNATURE */
    if (rc == 0) {
	rc = Array_Scan(&signatureBin,	/* output binary, freed @2 */
			&signatureBinSize ,
			signature);	/* input string */
	
    }
    /* unmarshal the signature stream back to a TPMT_SIGNATURE structure */
    TPMT_SIGNATURE 	tpmtSignature;
    tmpptr = signatureBin;
    tmpsize = signatureBinSize;
    if (rc == 0) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&tpmtSignature, &tmpptr, &tmpsize, TRUE);
    }
    /* read the nonce from the attestlog based on the hostname */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @3 */	
    }
    /* in machines db, for host, get AK certificate
     */
    MYSQL_RES 		*machineResult1 = NULL;
    char 		*machineId = NULL;		/* row being updated */
    const char 		*akCertificatePem = NULL;
    const char 		*clientBootTime = NULL;
    unsigned int 	nextImaEventNum;		/* first new IMA event to be processed */
    unsigned int 	firstImaEventNum;		/* first IMA event number processed */
    const char 		*imapcr;
    
    if (rc == 0) {
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @4 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				&clientBootTime,	/* boottime */
				&firstImaEventNum,	/* imaevents */
				&imapcr,		/* imapcr */
				&machineResult1,	/* freed @5 */
				mysql,
				hostname);
	if (rc != 0) {
	    printf("ERROR: processQuote: row for hostname %s does not exist in machine table\n",
		   hostname);  
	    rc = ACE_NOT_ENROLLED;
	}
	else if (akCertificatePem == NULL) {
	    printf("ERROR: processQuote: "
		   "row for hostname %s has invalid certificate in machine table\n",
		   hostname);  
	    rc = ACE_INVALID_CERT;
	}
	else {
	    if (verbose) printf("INFO: processQuote: found machines DB entry for %s\n", hostname);  
	}
    }
    /* in attestlog, get nonce, quoteVerified to ensure nonce is only used once per quote.  Row was
       inserted at processNonce.  If the row does not exist, fatal client error */
    MYSQL_RES 		*attestLogResult = NULL;
    char 		*attestLogId = NULL;		/* row being updated */
    const char		*timestamp;			/* time that the nonce was generated */
    const char 		*nonceServerString = NULL;	/* nonce from server DB */
    const char 		*quoteVerifiedString = NULL;	/* boolean from server DB */
    if (rc == 0) {
	/* this is a client error, indicating a bad hostname, or a hostname for the first time and
	   no nonce was requested. */
	rc = SQ_GetAttestLogEntry(&attestLogId, 		/* freed @6 */
				  NULL,				/* boottime */
				  &timestamp,			/* timestamp */
				  &nonceServerString,		/* nonce */
				  NULL,				/* pcrselect */
				  NULL,				/* quote */
				  &quoteVerifiedString,		/* quoteverified */
				  NULL,				/* logverified */
				  &attestLogResult,		/* freed @7 */
				  mysql,
				  hostname);
	if (rc != 0) {
	    printf("ERROR: processQuote: row for hostname %s does not exist in attest table\n",
		   hostname);
	    rc = ACE_NONCE_MISSING;
	}
	/* The DB quoteverified is used as state.  When the nonce is created, it is null, indicating
	   that the nonce has not been used.  After a quote, quoteverified is set true or false,
	   indicating that the nonce has been used. */
	else if (quoteVerifiedString != NULL) {
	    char 	query[QUERY_LENGTH_MAX];
	    quoteVerified = FALSE;	/* quote nonce */
	    printf("ERROR: processQuote: nonce for hostname %s already used\n", hostname);
	    /* since no attestlog entry was created during the nonce stage, create it here */
	    if (rc == 0) {
		int irc = snprintf(query, QUERY_LENGTH_MAX,
				   "insert into attestlog "
				   "(userid, hostname, timestamp, nonce, pcrselect, boottime) "
				   "values ('%s','%s','%s','%s','%s','%s')",
				   "unknown", hostname, "0000-00-00 00:00:00", "",
				   "", "0000-00-00 00:00:00");
		if (irc >= QUERY_LENGTH_MAX) {
		    printf("ERROR: processQuote: SQL query overflow\n");
		    rc = ASE_SQL_ERROR;
		}
	    }
	    if (rc == 0) {
		rc = SQ_Query(NULL, mysql, query);
	    }
	    /* Since the previous entry is not a new nonce, that attestlog entry should not be
	       reused.  Free the previous attestLogId attestLogResult.  A new entry will now be
	       created */
	    free(attestLogId);			/* @6 */
	    SQ_FreeResult(attestLogResult);	/* @7 */
	    attestLogId = NULL;
	    attestLogResult = NULL;
	    if (rc == 0) {
		rc = SQ_GetAttestLogEntry(&attestLogId, 	/* freed @6 */
					  NULL,			/* boottime */
					  NULL,			/* timestamp */
					  NULL,			/* nonce */
					  NULL,			/* pcrselect */
					  NULL,			/* quote */
					  NULL,			/* quoteverified */
					  NULL,			/* logverified */
					  &attestLogResult,	/* freed @7 */
					  mysql,
					  hostname);
	    }
	    /* since the next attestation should be a full log, not incremental, reset the boot time
	       in the machines DB */
	    if (rc == 0) {
		int irc = snprintf(query, QUERY_LENGTH_MAX,
				   "update machines set boottime = '%s', "
				   "imaevents = '%u', imapcr = '%s' "
				   "where id = '%s'",
				   "0000-00-00 00:00:00",
				   0,
				   "0000000000000000000000000000000000000000000000000000000000000000",
				   machineId);
		if (irc >= QUERY_LENGTH_MAX) {
		    printf("ERROR: processQuote: SQL query overflow\n");
		    rc = ASE_SQL_ERROR;
		}
	    }
	    if (rc == 0) {
		rc = SQ_Query(NULL, mysql, query);
	    }
	}
	else {
	    if (verbose) printf("INFO: processQuote: found attestlog DB entry for %s\n", hostname);  
	}
    }
    /* Validate the quote signature */
    if ((rc == 0) && quoteVerified) {
	rc = verifyQuoteSignature(&quoteVerified,	/* result */
				  quotedBin,		/* message */
				  quotedBinSize,	/* message size */
				  akCertificatePem,	/* public key */
				  &tpmtSignature);	/* signature */
    }
    /* unmarshal the TPM2B_ATTEST quoted structure */
    TPMS_ATTEST tpmsAttest;
    if ((rc == 0) && quoteVerified) {
	tmpptr = quotedBin;		/* so actual pointers don't move */
	tmpsize= quotedBinSize;
	rc = TSS_TPMS_ATTEST_Unmarshalu(&tpmsAttest, &tmpptr, &tmpsize);
	if (rc != 0) {
	    printf("ERROR: processQuote: cannot unmarshal client quoted structure\n");  
	}
    }
    /* validate that the nonce / extraData in the quoted is what was supplied to the client */
    if ((rc == 0) && quoteVerified) {
	rc = verifyQuoteNonce(&quoteVerified,		/* boolean result */
			      nonceServerString,	/* server */
			      &tpmsAttest);		/* client */
    }
    /* update attestlog DB status, quote data and quote verified */
    if (rc == 0) {
	rc = processQuoteResults(cmdJson, quoteVerified, attestLogId, mysql);
    }
    /* get the previous PCRs from the attestlog, may be all zeros */
    const char *previousPcrsString[IMPLEMENTATION_PCR];   /* from quote, from database */
    MYSQL_RES  *attestLogPcrResult = NULL;
    if ((rc == 0) && quoteVerified) {
	if (verbose) printf("INFO: processQuote: Retrieve previous PCRs\n");
	rc = SQ_GetAttestLogPCRs(NULL,
				 previousPcrsString,
				 &attestLogPcrResult,	/* freed @8 */
				 mysql,
				 hostname);
    }
    /* process the BIOS event log if sent by the client, else use the previous PCRs */
    unsigned int 	eventNum = 0;		/* BIOS events processed */
    uint8_t		pcrNum;
    size_t 		quotePcrsSha256BinLength[IMPLEMENTATION_PCR];
    uint8_t 		*quotePcrsSha256Bin[IMPLEMENTATION_PCR];
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	quotePcrsSha256Bin[pcrNum] = NULL;			/* for free, in case of error */
    }
    if ((rc == 0) && quoteVerified) {
	if (verbose) printf("INFO: processQuote: Process BIOS entries, pass 1\n");
	rc = processBiosEntries20Pass1(&eventNum,		/* events processed */
				       quotePcrsSha256BinLength,
				       quotePcrsSha256Bin,	/* freed @10 */
				       previousPcrsString,
				       cmdJson);
    }
    /* process the IMA log.  Stop when the PCRs match the quote digest, and return the last entry
       processed. */
    if ((rc == 0) && quoteVerified) {
	if (verbose) printf("INFO: processQuote: Process IMA entries, pass 1\n");
	rc = processImaEntries20Pass1(&logVerified,		/* PCR digest matches quote */
				      &nextImaEventNum,		/* first in next attestation */
				      firstImaEventNum,	/* first new IMA event to be processed */
				      quotePcrsSha256BinLength,
				      quotePcrsSha256Bin,	/* freed @10 */
				      previousPcrsString,
				      &tpmsAttest,
				      cmdJson);
    }
    if ((rc == 0) && quoteVerified) {
	if (logVerified) {
	    if (vverbose) printf("processQuote: After processImaEntries first %u - next %u\n",
				 firstImaEventNum, nextImaEventNum);
	}
	else {
	    if (verbose) printf("ERROR: processQuote: Event logs do not match quote\n");
	}
    }
    /* update the attestdb with the boolean log verified result if at least one new IMA entry was
       processed */
    if ((rc == 0) && quoteVerified && (eventNum > 0)) {
	rc = processBiosLogResults(logVerified,
				   eventNum,		/* BIOS events processed */
				   attestLogId, mysql);
    }
    if ((rc == 0) && quoteVerified && (firstImaEventNum < nextImaEventNum)) {
	rc = processImaLogResults(logVerified,
				  nextImaEventNum,		/* next IMA event number to be processed */
				  attestLogId, mysql);
    }
    /*
      Processing once the quote is verified completely
    */
    /* for the free (do even on error cases since the free is unconditional) */
    char	*quotePcrsSha256String[IMPLEMENTATION_PCR];
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	quotePcrsSha256String[pcrNum] = NULL;
    }
    /* convert the reconstructed PCRs from binary to string for the DB store */
    if ((rc == 0) && quoteVerified) {
	rc = pcrBinToString(quotePcrsSha256String,	/* freed @12 */
			    TPM_ALG_SHA256,
			    quotePcrsSha256Bin);
    }
    if (quoteVerified && logVerified) {
	/* update the machines DB with the IMA state (IMA pcr and IMA events processed) for a
	   subsequent incremental log */
	if (rc == 0) {
	    rc= updateImaState(nextImaEventNum,		/* next IMA event number to be processed */
			       quotePcrsSha256String[TPM_IMA_PCR],
			       machineId, mysql);
	}
	/* add validated quote PCRs to attestlog DB */
	if (rc == 0) {
	    rc = processQuotePCRs(quotePcrsSha256String, attestLogId, mysql);
	}
	/* validate quote PCRs against white list, or initialize the white list */
	if (rc == 0) {
	    rc = processQuoteWhiteList(quotePcrsSha256String, hostname, attestLogId, mysql);
	}
	/* determine whether BIOS PCRs match the previous quote. If no previous quote, PCRs do not
	   match.  */
	if (rc == 0) {
	    if (verbose) printf("INFO: processQuote: Check previous BIOS PCRs\n");  
	    rc = checkBiosPCRsMatch(&previousBiosPcrs,		/* TRUE if previous BIOS PCRs */
				    &biosPcrsMatch,		/* TRUE if previous PCRs match */
				    (const char **)quotePcrsSha256String,
				    TRUE,			/* tpm20 */
				    attestLogId, mysql,
				    hostname);
	}
	/* store the BIOS entries in the DB */
	if (rc == 0) {
	    if (verbose) printf("INFO: processQuote: Second pass, storing BIOS entries\n");
	    rc = processBiosEntries20Pass2(hostname,	/* for DB row */
					   timestamp,	/* for DB row */
					   cmdJson,	/* client command */
					   mysql);
	}
    }
    /* store the IMA entries in the DB */
    if (logVerified && quoteVerified && (firstImaEventNum < nextImaEventNum)) {
	int imasigver;
	if (rc == 0) {
	    if (verbose) printf("INFO: processQuote: "
				"Second pass, validating IMA entries %u - %u\n",
				firstImaEventNum, nextImaEventNum);
	    rc = processImaEntriesPass2(&imasigver,
					hostname,		/* for DB row */
					clientBootTime,		/* for DB row */
					timestamp,		/* for DB row */
					cmdJson,		/* client command */
					firstImaEventNum,	/* first IMA event processed */
					nextImaEventNum,	/* next IMA event number to be processed */
					attestLogId,
					mysql);	
	}
    }
    /*
      create the quote return json
    */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @9 */
    if (rc1 == 0) {
	if (rc == 0) {
	    if (!quoteVerified) {
		rc = ACE_QUOTE_SIGNATURE;
	    }
	    else if (!logVerified) {
		rc = ACE_EVENT;
	    }
	}
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("quote"));
	}
	/* processing error */
	else {
	    rc1 = JS_Rsp_AddError(response, rc);
	}
	if (rc1 == 0) {	
	    rc = JS_ObjectSerialize(rspLength,
				    (char **)rspBuffer,	/* freed by caller */
				    response);		/* @9 */
	}
    }
    /* could not construct response */
    else {
	rc = rc1;
    }
    free(quotedBin);			/* @1 */
    free(signatureBin);			/* @2 */ 
    SQ_Close(mysql);			/* @3 */
    free(machineId);			/* @4 */
    SQ_FreeResult(machineResult1);	/* @5 */
    free(attestLogId);			/* @6 */
    SQ_FreeResult(attestLogResult);	/* @7 */
    SQ_FreeResult(attestLogPcrResult);	/* @8 */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	free(quotePcrsSha256Bin[pcrNum]);		/* @10 */
	free(quotePcrsSha256String[pcrNum]);		/* @12 */			
    }
    return rc;
}

#ifdef TPM_TPM12

/* processQuote12 processes the client quote and creates the client response.

   The client command is:

   {
   "command":"quote12",
   "hostname":"cainl12.watson.ibm.com",
   "pcrdata":"0003ff0700018673cb4457608816c11988c07ad46cba2ccdda73",
   "versioninfo":"0030010212a400020349424d000000",
   "signature":"584ef01589b918bcfc16270510457ea6d1b42a24402eb5f..."
   }

   The server response is:
     
   {
   "response":"quote"
   }
     
   ~~

   Verifies the quote signature
   Verifies the nonce
   Walks the BIOS event log and reconstructs the PCRs (pass 1)
   Walks the IMA event log until the PCRs match the quote (pass 1)
   Checks the PCR white list if available
   Validates the IMA event (pass 2)
   
   Initializes the machines PCR white list
   Initializes the machines imaevents, imapcr, boottime

   Updates the attestlog with

   - raw quote json, excluding the event logs
   - quote signature verified
   - event logs verified, match the quote
   - the BIOS events and IMA event processed
   - reconstructed PCRs
   - validation of the PCR white list
   - whether the BIOS PCRs changed since the last attestation

   Updates the machines DB with

   - next IMA event to be processed in an incremental attestation
   - IMA PCR to be used in an incremental attestation
   - PCR white list if the first attestation

   Adds a bioslog entry with the BIOS events (pass 2)
   Adds an imalog entry with the IMA events (pass 2)

*/

static uint32_t processQuote12(unsigned char **rspBuffer,		/* freed by caller */
			       uint32_t *rspLength,
			       json_object *cmdJson,
			       unsigned char *cmdBuffer)
{
    uint32_t  		rc = 0;	
    /* from client */
    const char 		*hostname = NULL;
    const char 		*pcrDataString = NULL;	/* string from json */
    const char 		*versionInfo = NULL;	/* string from json */
    unsigned char 	*versionInfoBin = NULL;
    size_t 		versionInfoBinSize;
    const char 		*signature = NULL;	/* string from json */
    unsigned char 	*signatureBin = NULL;
    size_t 		signatureBinSize;

    /* status flags */
    unsigned int 	quoteVerified = FALSE;	/* TRUE if quote signature verified AND PCRs match
						   quote digest AND nonce matches */
    unsigned int 	logVerified = FALSE;	/* PCR digest matches event logs */

    unsigned int 	biosPcrsMatch = FALSE; 	/* TRUE if previous valid quote and PCRs did not
						   change */
    unsigned int	previousBiosPcrs = FALSE;	/* TRUE is there was a previous valid
							   quote */

    cmdBuffer = cmdBuffer;
    if (vverbose) printf("INFO: processQuote12: Entry\n");
    /*
      Get data from client command json
    */
    /* Get the client hostname.  Do this first since this DB column should be valid. */
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    /* Get the client pcrdata */
    if (rc == 0) {
	rc = JS_ObjectGetString(&pcrDataString, "pcrdata", ACS_JSON_QUOTED_MAX, cmdJson);
    }
    /* convert the pcrdata to binary */
    unsigned char 	*pcrDataBin = NULL;
    size_t 		pcrDataBinSize;
    if (rc == 0) {
	rc = Array_Scan(&pcrDataBin ,		/* output binary, freed @2 */
			&pcrDataBinSize,
			pcrDataString);		/* input string */
    }    
    /* Get the client versionInfo */
    if (rc == 0) {
	rc = JS_ObjectGetString(&versionInfo, "versioninfo", ACS_JSON_QUOTED_MAX, cmdJson);
    }
    /* convert the versionInfo to binary */
    if (rc == 0) {
	rc = Array_Scan(&versionInfoBin ,	/* output binary, freed @3 */
			&versionInfoBinSize,
			versionInfo);		/* input string */
    }    
    /* Get the client quote signature */
    if (rc == 0) {
	rc = JS_ObjectGetString(&signature, "signature", ACS_JSON_SIGNATURE_MAX, cmdJson);
    }
    /* convert the signature to binary.  In TPM 1.2, this is a raw RSA signature. */
    if (rc == 0) {
	rc = Array_Scan(&signatureBin,	/* output binary, freed @4 */
			&signatureBinSize,
			signature);	/* input string */
	
    }
    /* read the nonce from the attestlog based on the hostname */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @5 */	
    }
    /* in machines db, select id, certificate, boottime using hostname and active
       in attestlog, select hostname, order by id, get nonce, pcrselect
    */
    MYSQL_RES 		*machineResult = NULL;
    char 		*machineId = NULL;		/* row being updated */
    const char 		*akCertificatePem = NULL;
    const char 		*clientBootTime = NULL;
    unsigned int 	nextImaEventNum;		/* next IMA event to be processed */
    unsigned int 	firstImaEventNum;		/* first IMA event number processed */
    const char 		*imapcr;

    if (rc == 0) {
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @6 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				&clientBootTime,	/* boottime */
				&firstImaEventNum,	/* imaevents */
				&imapcr,		/* imapcr */
				&machineResult,		/* freed @7 */
				mysql,
				hostname);
	if (rc != 0) {
	    printf("ERROR: processQuote12: row for hostname %s does not exist in machine table\n",
		   hostname);  
	    rc = ACE_NOT_ENROLLED;
	}
	else if (akCertificatePem == NULL) {
	    printf("ERROR: processQuote12: "
		   "row for hostname %s has invalid certificate in machine table\n",
		   hostname);  
	    rc = ACE_INVALID_CERT;
	}
	else {
	    if (verbose) printf("INFO: processQuote12: found machines DB entry for %s\n",
				hostname);  
	}
    }    
    /* in attestlog, get nonce, quoteVerified to ensure nonce is only used once per quote.  Row was
       inserted at processNonce.  If the row does not exist, fatal client error */
    MYSQL_RES 		*attestLogResult = NULL;
    char 		*attestLogId = NULL;		/* row being updated */
    const char		*timestamp;			/* time that the nonce was generated */
    const char 		*nonceServerString = NULL;	/* nonce from server DB */
    const char 		*quoteVerifiedString = NULL;	/* boolean from server DB */
    if (rc == 0) {
	/* this is a client error, indicating a bad hostname, or a hostname for the first time and
	   no nonce was requested. */
	rc = SQ_GetAttestLogEntry(&attestLogId, 		/* freed @8 */
				  NULL,				/* boottime */
				  &timestamp,			/* timestamp */
				  &nonceServerString,		/* nonce */
				  NULL,				/* pcrselect */
				  NULL,				/* quote */
				  &quoteVerifiedString,		/* quoteverified */
				  NULL,				/* logverified */
				  &attestLogResult,		/* freed @9 */
				  mysql,
				  hostname);
	if (rc != 0) {
	    printf("ERROR: processQuote12: row for hostname %s does not exist in attest table\n",
		   hostname);
	    rc = ACE_NONCE_MISSING;
	}
	/* The DB quoteverified is used as state.  When the nonce is created, it is null, indicating
	   that the nonce has not been used.  After a quote, quoteverified is set true or false,
	   indicating that the nonce has been used. */
	else if (quoteVerifiedString != NULL) {
	    printf("ERROR: processQuote12: nonce for hostname %s already used\n", hostname);  
	    rc = ACE_NONCE_USED;
	}
	else {
	    if (verbose) printf("INFO: processQuote12: found attestlog DB entry for %s\n",
				hostname);  
	}
    }
    /* Validate the quote signature */
    if (rc == 0) {
	rc = verifyQuoteSignature12(&quoteVerified,	
				    nonceServerString,
				    pcrDataBin,
				    pcrDataBinSize,
				    versionInfoBin,
				    versionInfoBinSize,
				    akCertificatePem,
				    signatureBin,
				    signatureBinSize);
    }
    TPM_PCR_INFO_SHORT pcrInfoShort;
    if (rc == 0) {
	uint8_t *buffer = pcrDataBin;
	uint32_t size = pcrDataBinSize;
	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshalu(&pcrInfoShort, &buffer, &size);
	if (rc != 0) {
	    printf("ERROR: processQuote12: cannot unmarshal client pcrData structure\n");  
	}
    }
    /* validating the client nonce is not required since the server nonce was used to reconstruct
       the message */
    /* update attestlog DB status, quote data and quote verified */
    if (rc == 0) {
	rc = processQuoteResults12(cmdJson, quoteVerified, attestLogId, mysql);
    }
    /* get the previous PCRs from the attestlog, may be all zeros */
    const char *previousPcrsString[IMPLEMENTATION_PCR]; /* from quote, from database */
    MYSQL_RES  *attestLogPcrResult = NULL;
    if (rc == 0) {
	if (verbose) printf("INFO: processQuote12: Retrieve previous PCRs\n");
	rc = SQ_GetAttestLogPCRs(NULL,
				 previousPcrsString,
				 &attestLogPcrResult,	/* freed @10 */
				 mysql,
				 hostname);
    }
    /* process the BIOS event log if sent by the client, else use the previous PCRs */
    unsigned int 	eventNum = 0;		/* BIOS events processed */
    uint8_t		pcrNum;
    size_t 		quotePcrsSha1BinLength[IMPLEMENTATION_PCR];
    uint8_t 		*quotePcrsSha1Bin[IMPLEMENTATION_PCR];
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	quotePcrsSha1Bin[pcrNum] = NULL;			/* for free, in case of error */
    }
    if ((rc == 0) && quoteVerified) {
	if (verbose) printf("INFO: processQuote12: Process BIOS entries, pass 1\n");
	rc = processBiosEntries12Pass1(&eventNum,		/* events processed */
				       quotePcrsSha1BinLength,
				       quotePcrsSha1Bin,	/* freed @11 */
				       previousPcrsString,
				       cmdJson);
    }
    /* process the IMA log.  Stop when the PCRs match the quote digest, and return the last entry
       processed. */
    if ((rc == 0) && quoteVerified) {
	if (verbose) printf("INFO: processQuote12: Process IMA entries, pass 1\n");
	rc = processImaEntries12Pass1(&logVerified,		/* PCR digest matches quote */
				      &nextImaEventNum,		/* next IMA event to be processed */
				      firstImaEventNum,		/* first new IMA event to be
								   processed */
				      quotePcrsSha1BinLength,
				      quotePcrsSha1Bin,		/* freed @11 */
				      previousPcrsString,
				      &pcrInfoShort,
				      cmdJson);
    }
    if ((rc == 0) && logVerified) {
	if (vverbose) printf("processQuote12: After processImaEntries first %u - last %u\n",
			     firstImaEventNum, nextImaEventNum);
    }
    /* update the attestdb with the boolean log verified result if at least one new IMA entry was
       processed */
    if ((rc == 0) && (firstImaEventNum < nextImaEventNum)) {
	rc = processLogResults(logVerified, eventNum,
			       nextImaEventNum,		/* next  IMA event number to be processed */
			       attestLogId, mysql);
    }    
    /*
      Processing once the quote is verified completely
    */
    /* for the free (do even on error cases since the free is unconditional) */
    char	*quotePcrsSha1String[IMPLEMENTATION_PCR];
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	quotePcrsSha1String[pcrNum] = NULL;
    }
    /* convert the reconstructed PCRs from binary to string for the DB store */
    if (rc == 0) {
	rc = pcrBinToString(quotePcrsSha1String,	/* freed @12 */
			    TPM_ALG_SHA1,
			    quotePcrsSha1Bin);
    }
    if (quoteVerified && logVerified) {
	/* update the machines DB with the IMA state (IMA pcr and IMA events processed) for a
	   subsequent incremental log */
	if (rc == 0) {
	    rc= updateImaState(nextImaEventNum,		/* next IMA event number to be processed */
			       quotePcrsSha1String[TPM_IMA_PCR],
			       machineId, mysql);
	}    
 	/* add validated quote PCRs to attestlog DB */
	if (rc == 0) {
	    rc = processQuotePCRs(quotePcrsSha1String, attestLogId, mysql);
	}
 	/* validate quote PCRs against white list, or initialize the white list */
	if (rc == 0) {
	    rc = processQuoteWhiteList(quotePcrsSha1String, hostname, attestLogId, mysql);
	}
	/* determine whether BIOS PCRs match the previous quote. If no previous quote, PCRs do not
	   match.  */
	if (rc == 0) {
	    if (verbose) printf("INFO: processQuote12: Check previous BIOS PCRs\n");  
	    rc = checkBiosPCRsMatch(&previousBiosPcrs,		/* TRUE if previous BIOS PCRs */
				    &biosPcrsMatch,		/* TRUE if previous PCRs match */
				    (const char **)quotePcrsSha1String,
				    FALSE,			/* tpm 1.2 */
				    attestLogId, mysql,
				    hostname);
	}
	/* store the BIOS entries in the DB */
	if (rc == 0) {
	    if (verbose) printf("INFO: processQuote12: Second pass, storing BIOS entries\n");
	    rc = processBiosEntries12Pass2(hostname,	/* for DB row */
					   timestamp,	/* for DB row */
					   cmdJson,	/* client command */
					   mysql);
	}
    }
    /* store the IMA entries in the DB */
    if (logVerified && (firstImaEventNum < nextImaEventNum)) {
	int imasigver;
	if (rc == 0) {
	    if (verbose) printf("INFO: processQuote12: "
				"Second pass, validating IMA entries %u - %u\n",
				firstImaEventNum, nextImaEventNum);
	    rc = processImaEntriesPass2(&imasigver,
					hostname,		/* for DB row */
					clientBootTime,		/* for DB row */
					timestamp,		/* for DB row */
					cmdJson,		/* client command */
					firstImaEventNum,	/* first IMA event processed */
					nextImaEventNum,	/* next IMA event number to be processed */
					attestLogId,
					mysql);	
	}
    }
    /*
      create the quote return json
    */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @14 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("quote"));
	}
	/* processing error */
	else {
	    rc1 = JS_Rsp_AddError(response, rc);
	}
	if (rc1 == 0) {	
	    rc = JS_ObjectSerialize(rspLength,
				    (char **)rspBuffer,	/* freed by caller */
				    response);		/* @14 */
	}
    }
    /* could not construct response */
    else {
	rc = rc1;
    }
    free(pcrDataBin);			/* @2 */ 
    free(versionInfoBin);		/* @3 */ 
    free(signatureBin);			/* @4 */ 
    SQ_Close(mysql);			/* @5 */
    free(machineId);			/* @6 */
    SQ_FreeResult(machineResult);	/* @7 */
    free(attestLogId);			/* @8 */
    SQ_FreeResult(attestLogResult);	/* @9 */
    SQ_FreeResult(attestLogPcrResult);	/* @10 */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	free(quotePcrsSha1Bin[pcrNum]);		/* @11 */
	free(quotePcrsSha1String[pcrNum]);	/* @12 */			
    }
    return rc;
}

#endif /* TPM_TPM12 */

/* makePcrSelect20() creates the TPM 2.0 PCR select structure, PCR0-10 SHA256 for BIOS and PCR10
   SHA-256 for IMA. */

static void makePcrSelect20(TPML_PCR_SELECTION *pcrSelection)
{
    pcrSelection->count = 2;		/* two banks */
    /* TPMS_PCR_SELECTION */
    pcrSelection->pcrSelections[0].hash = TPM_ALG_SHA256;
    pcrSelection->pcrSelections[0].sizeofSelect = 3;
    pcrSelection->pcrSelections[0].pcrSelect[0] = 0xff;	/* PCR 0-9 */
    pcrSelection->pcrSelections[0].pcrSelect[1] = 0x07;	/* PCR 10, IMA_PCR */
    pcrSelection->pcrSelections[0].pcrSelect[2] = 0x00;
    /* TPMS_PCR_SELECTION */
    pcrSelection->pcrSelections[1].hash = TPM_ALG_SHA1;
    pcrSelection->pcrSelections[1].sizeofSelect = 3;
    pcrSelection->pcrSelections[1].pcrSelect[0] = 0x00;
    pcrSelection->pcrSelections[1].pcrSelect[1] = 0x00;
    pcrSelection->pcrSelections[1].pcrSelect[2] = 0x00;
    return;
}

#ifdef TPM_TPM12

/* makePcrSelect12() creates the TPM 1.2 PCR select structure, PCR0-10 SHA256 for BIOS and PCR10
   SHA-256 for IMA. */

static void makePcrSelect12(uint32_t *valueSize,	/* size of PCR array */
			    TPM_PCR_SELECTION *pcrSelection)
{
    pcrSelection->sizeOfSelect = 3;
    pcrSelection->pcrSelect[0] = 0xff;		/* PCR 0-9 */
    pcrSelection->pcrSelect[1] = 0x07;		/* PCR 10, IMA_PCR */
    pcrSelection->pcrSelect[2] = 0x00;
    *valueSize = (11 * SHA1_DIGEST_SIZE);	/* 11 PCRs selected */
    return;
}

#endif

/* getBiosPCRselect() returns a PCR select of only the BIOS PCRs in a TPM 1.2/2.0 common format */

static void getBiosPCRselect(uint8_t *sizeOfSelect,
			     uint8_t pcrSelect[],
			     int tpm20)
{
#ifdef TPM_TPM12
    if (tpm20) {
#else
	tpm20 = tpm20;
#endif
	TPML_PCR_SELECTION pcrSelection;
	makePcrSelect20(&pcrSelection);
	*sizeOfSelect = pcrSelection.pcrSelections[0].sizeofSelect;
	memcpy(pcrSelect, pcrSelection.pcrSelections[0].pcrSelect, *sizeOfSelect);
#ifdef TPM_TPM12
    }
    else {	/* 1.2 */
	uint32_t valueSize;
	TPM_PCR_SELECTION pcrSelection;
	makePcrSelect12(&valueSize, &pcrSelection);
	*sizeOfSelect = pcrSelection.sizeOfSelect;
	memcpy(pcrSelect, pcrSelection.pcrSelect, *sizeOfSelect);
     }
#endif
    /* mask off IMA PCR */
    pcrSelect[TPM_IMA_PCR / 8] &= ~(1 << (TPM_IMA_PCR % 8));
    return;
}

/* pcrBinToString() converts a PCR from binary to a hexascii string, with the length determined by
   the hash algorithm */

static uint32_t pcrBinToString(char *pcrsString[],	/* freed by caller */
			       TPMI_ALG_HASH halg,
			       uint8_t **pcrsBin)
{
    uint32_t 	rc = 0;
    uint32_t	pcrNum;
    uint16_t	sizeInBytes = TSS_GetDigestSize(halg);

    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	Array_PrintMalloc(&pcrsString[pcrNum],			/* freed by caller */
			  pcrsBin[pcrNum], sizeInBytes);
#if 0
	if (vverbose) printf("pcrBinToString: PCR %u %s\n", pcrNum, pcrsString[pcrNum]);
	if (vverbose) TSS_PrintAll("pcrBinToString: PCR",
				   (uint8_t *)pcrsBin[pcrNum], sizeInBytes);
#endif
    }
    return rc;
}

/* makePcrStream20() concatenates the selected PCRs into a stream. pcrBinStream must be large enough
   to hold the stream.

   This is used to create the pcrDigest for a TPM 2.0 quote verification.
*/

static uint32_t makePcrStream20(unsigned char 	*pcrBinStream,
				size_t 		*pcrBinStreamSize,
				unsigned char 	**pcrsSha256Bin,
				TPML_PCR_SELECTION *pcrSelection)
{
    uint32_t  		rc = 0;
    uint32_t 		bank;
    unsigned int 	pcrNum;

    *pcrBinStreamSize = 0;
    /* iterate through banks / hash algorithms */
    for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {
	TPMI_ALG_HASH halg = pcrSelection->pcrSelections[bank].hash;
	/* iterate through PCRs */
	for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {

	    int selected =			/* bitmap, is this PCR selected */
		(pcrSelection->pcrSelections[bank].pcrSelect[pcrNum / 8]) &
		(1 << (pcrNum % 8));
	    if (selected) {
		if (vverbose) printf("makePcrStream20: using bank %u PCR %u\n", bank, pcrNum);
		if (halg == TPM_ALG_SHA256) {
#if 0
		    if (vverbose) Array_Print(NULL, "makePcrStream20: PCR", TRUE,
					      pcrsSha256Bin[pcrNum], SHA256_DIGEST_SIZE);
#endif
		    memcpy(pcrBinStream + *pcrBinStreamSize,
			   pcrsSha256Bin[pcrNum], SHA256_DIGEST_SIZE);
		    *pcrBinStreamSize += SHA256_DIGEST_SIZE;
		}
		/* since the server only uses sha256 for tpm20, something is inconsistent in the
		   code */
		else {
		    printf("ERROR: makePcrStream20: Hash algorithm %04x not supported\n", halg);
		    rc = ASE_BAD_ALG;
		}
	    }
	}
    }
    return rc;
}

#ifdef TPM_TPM12

/* makePcrStream12() concatenates the PCR selection and selected PCRs into a stream. pcrBinStream
   must be large enough to hold the stream.

   This is used to create the pcrDigest for a TPM 1.2 quote digestAtRelease.
*/

static uint32_t makePcrStream12(unsigned char 	*pcrBinStream,
				uint16_t	*pcrBinStreamSize,
				unsigned char 	**pcrsSha1Bin)
{
    uint32_t  		rc = 0;
    unsigned int 	pcrNum;
    TPM_PCR_SELECTION 	pcrSelection;
    unsigned char 	*tmpptr = pcrBinStream;		/* movable pointer */
    uint32_t 		valueSize;

    *pcrBinStreamSize = 0;

    if (rc == 0) {
	/* create the TPM 1.2 PCR selection */
	makePcrSelect12(&valueSize, &pcrSelection);	
	if (vverbose) printf("makePcrStream12: valueSize %u\n", valueSize);
	/* serialize it to the stream */
	rc = TSS_TPM_PCR_SELECTION_Marshalu(&pcrSelection, pcrBinStreamSize, &tmpptr, NULL);
    }
    /* append valueSize */
    if (rc == 0) {
	uint32_t valueSizeNbo = htonl(valueSize);
	memcpy(tmpptr, (uint8_t *)&valueSizeNbo, sizeof(uint32_t));
	*pcrBinStreamSize += sizeof(uint32_t);
	tmpptr += sizeof(uint32_t);
    }
    /* iterate through PCRs */
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {

	int selected =			/* bitmap, is this PCR selected */
	    (pcrSelection.pcrSelect[pcrNum / 8]) & (1 << (pcrNum % 8));
	if (selected) {
	    if (vverbose) printf("makePcrStream12: using PCR %u\n", pcrNum);
	    if (vverbose) Array_Print(NULL, "makePcrStream12: PCR", TRUE,
				      pcrsSha1Bin[pcrNum], SHA1_DIGEST_SIZE);
	    memcpy(tmpptr, pcrsSha1Bin[pcrNum], SHA1_DIGEST_SIZE);
	    *pcrBinStreamSize += SHA1_DIGEST_SIZE;
	    tmpptr += SHA1_DIGEST_SIZE;
	}
    }
    if (vverbose) printf("makePcrStream12: Result length %u\n", *pcrBinStreamSize);
    if (vverbose) Array_Print(NULL, "makePcrStream12: Result", TRUE,
			      pcrBinStream, *pcrBinStreamSize);
    return rc;
}

#endif /* TPM_TPM12 */

/* initializePCRs() is used on a new boot cycle.  It initializes all attestlog DB PCRs to all zero.
 */

static uint32_t initializePCRs(MYSQL *mysql,
			       const char *hostname)
{
    uint32_t  		rc = 0;

    /* get the ID of the DB entry */
    char 		*attestLogId = NULL;		/* row being updated */
    MYSQL_RES 		*attestLogResult = NULL;
    if (rc == 0) {
	rc = SQ_GetAttestLogEntry(&attestLogId, 		/* freed @1 */
				  NULL,				/* boottime */
				  NULL,				/* timestamp */
				  NULL,				/* nonce */
				  NULL,				/* pcrselect */
				  NULL,				/* quote */
				  NULL,				/* quoteverified */
				  NULL,				/* logverified */
				  &attestLogResult,		/* freed @2 */
				  mysql,
				  hostname);
	/* this should never fail, since a previous step wrote the attestlog DB */
	if (rc != 0) {
	    printf("ERROR: initializePCRs: row for hostname %s does not exist in attest table\n",
		   hostname);
	    rc = ASE_SQL_QUERY;
	}
    }
    uint32_t pcrNum;
    char 	query[QUERY_LENGTH_MAX];
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (rc == 0) {
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "update attestlog set pcr%02usha1 = '%s' where id = '%s'",
			       pcrNum,
			       "00000000000000000000"
			       "00000000000000000000",
			       attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: initializePCRs: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
	if (rc == 0) {
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "update attestlog set pcr%02usha256 = '%s' where id = '%s'",
			       pcrNum,
			       "00000000000000000000000000000000"
			       "00000000000000000000000000000000",
			       attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: initializePCRs: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    free(attestLogId);			/* @1 */
    SQ_FreeResult(attestLogResult);	/* @2 */
    return rc;
}

/* copyPreviousPCRs() copies the previous attestation PCRs to the current attestlog DB entry.  This
   is used when the BIOS log is not requested and the IMA log is incremental. */

static uint32_t copyPreviousPCRs(const char *boottime,
				 MYSQL *mysql,
				 const char *hostname)
{
    uint32_t  		rc = 0;
    MYSQL_RES 		*previousPcrsResult = NULL;
    const char 		*previousPcrs[IMPLEMENTATION_PCR];
    
    if (rc == 0) {
	rc = SQ_GetPreviousPcrs(previousPcrs,
				&previousPcrsResult,	/* freed @1*/
				mysql,
				hostname,
				boottime);
    }
    char *attestLogId = NULL;
    MYSQL_RES *attestLogResult = NULL;
    if (rc == 0) {
	rc = SQ_GetAttestLogEntry(&attestLogId, 		/* freed @3 */
				  NULL,				/* boottime */
				  NULL,				/* timestamp */
				  NULL,				/* nonce */
				  NULL,				/* pcrselect */
				  NULL,				/* quote */
				  NULL,				/* quoteverified */
				  NULL,				/* logverified */
				  &attestLogResult,		/* freed @2 */
				  mysql,
				  hostname);

    }
    uint32_t pcrNum;
    char 	query[QUERY_LENGTH_MAX];
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (rc == 0) {
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "update attestlog set pcr%02usha256 = '%s' where id = '%s'",
			       pcrNum, previousPcrs[pcrNum],
			       attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: initializePCRs: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    SQ_FreeResult(previousPcrsResult);		/* @1 */
    SQ_FreeResult(attestLogResult);		/* @2 */
    free(attestLogId);				/* @3 */

    return rc;
}

/* checkBiosPCRsMatch() determines whether PCRs match the previous valid quote.

   If there was a previous successful quote, previousBiosPcrs is TRUE.  If the current BIOS PCRs
   match the previous value, biosPcrsMatch is TRUE, else FALSE.

   If there was no previous successful quote, previousBiosPcrs is FALSE and biosPcrsMatch is FALSE.

   The PCRs are strings, so the function is algorithm independent.
*/

static uint32_t checkBiosPCRsMatch(unsigned int *previousBiosPcrs,	/* boolean */
				   unsigned int *biosPcrsMatch,		/* boolean */
				   const char	*quotePcrsString[],
				   int 		tpm20,
				   const char 	*attestLogId,
				   MYSQL	*mysql,
				   const char 	*hostname)
{
    uint32_t  		rc = 0;
    MYSQL_RES 		*previousAttestLogResult = NULL;
    const char		*previousPcrsString[IMPLEMENTATION_PCR];

    *biosPcrsMatch = FALSE;		/* unless match detected */
    /* get the previous PCRs, algorithm independent strings  */
    if (rc == 0) {
	rc = SQ_GetPreviousPcrs(previousPcrsString,
				&previousAttestLogResult,	/* freed @1 */
				mysql,
				hostname,
				NULL);
    }
    /* if there was no previous successful attestation for this host */
    if (rc != 0) {			/* first time for this host */
	if (verbose) printf("INFO: checkBiosPCRsMatch: No previous PCRs, first attestation\n");
	*previousBiosPcrs = FALSE;
	rc = 0;
    }
    /* NULL means that previous attestations failed */
    else if ((previousPcrsString[0] == NULL)) {
	if (verbose)
	    printf("INFO: checkBiosPCRsMatch: No previous PCRs, previous attestations failed\n");
	*previousBiosPcrs = FALSE;
	rc = 0;
    }
    /* have previous PCRs to compare */
    else {
	
	*previousBiosPcrs = TRUE;
	*biosPcrsMatch = TRUE;
	uint8_t sizeOfSelect;
	uint8_t pcrSelect[((IMPLEMENTATION_PCR+7)/8)];
	getBiosPCRselect(&sizeOfSelect, pcrSelect, tpm20);
	/* check the BIOS PCR */
	if (vverbose) printf("checkBiosPCRsMatch: sizeOfSelect %u\n", sizeOfSelect);
	if (vverbose) TSS_PrintAll("checkBiosPCRsMatch: pcrSelect",
				   pcrSelect, sizeOfSelect);
	uint32_t pcrNum;
	for (pcrNum = 0 ; *biosPcrsMatch && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {

	    
	    int selected =			/* bitmap, is this PCR selected */
		(pcrSelect[pcrNum / 8]) & (1 << (pcrNum % 8));
	    if (selected) {
		if (vverbose) printf("checkBiosPCRsMatch: Check PCR %u\n", pcrNum );
		int irc;
		irc = strcmp(previousPcrsString[pcrNum], quotePcrsString[pcrNum]);
		/* PCR changed */
		if (irc != 0) {
		    if (verbose) printf("INFO: checkBiosPCRsMatch: PCR %u changed\n", pcrNum);
		    *biosPcrsMatch = FALSE;
		}
	    }
	}
	if (*biosPcrsMatch) {
	    if (verbose) printf("INFO: checkBiosPCRsMatch: PCRs did not change\n");
	}
    }
    /* PCRs change from previous value, only if there were previous
       PCRs */
    if ((rc == 0) && previousBiosPcrs) {
	char query[QUERY_LENGTH_MAX];
	if (rc == 0) {
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "update attestlog set pcrschanged = '%u' where id = '%s'",
			       !biosPcrsMatch, attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: checkBiosPCRsMatch: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }

    SQ_FreeResult(previousAttestLogResult);		/* @1 */
    previousAttestLogResult = NULL;
    return rc;
}

/* processBiosEntries20Pass1() does the first pass through the BIOS log entries that the client
   sends with the quote.

   For each entry, it extends a PCR.  They start at all zero after a reboot.

   It returns when all client BIOS log entries have been processed.  Returns eventNum = 0 if no
   events were processed.

   if
   client returned bios event log
   reconstruct current bios pcrs from event log

   else
   use previous bios pcrs as current bios pcrs

   mallocs the sha256 bank.  Freed by caller.
*/

/* handle a log with  SHA1 and SHA256 even though only SHA256 is of interest */

#define BIOS_LOG_ALGS 2

static uint32_t processBiosEntries20Pass1(unsigned int *eventNum,	/* events processed */
					  size_t quotePcrsSha256BinLength[],
					  uint8_t *quotePcrsSha256Bin[],  /* BIOS PCRs in quote,
									     freed by caller */
					  const char *previousPcrs[],
					  json_object *cmdJson)	/* client command, event log */
{
    uint32_t 		rc = 0;
    int			done = FALSE;
    uint32_t 		bankNum;
    uint32_t		pcrNum;
    TPMT_HA		biosPcrs[HASH_COUNT][IMPLEMENTATION_PCR];

    if (verbose) printf("INFO: processBiosEntries20Pass1: First pass, calculating BIOS PCRs\n");
    /* calculation starts with PCRs all zero, handles two banks */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	biosPcrs[0][pcrNum].hashAlg = TPM_ALG_SHA256;
	memset((uint8_t *)&biosPcrs[0][pcrNum].digest, 0, SHA256_DIGEST_SIZE);
	biosPcrs[1][pcrNum].hashAlg = TPM_ALG_SHA1;
	memset((uint8_t *)&biosPcrs[1][pcrNum].digest, 0, SHA1_DIGEST_SIZE);
    }
    /* The rest of the banks have no algorithm.  In the future, this could be table driven rather
       than hard coded to SHA-1 and SHA-256 */
    for (bankNum = BIOS_LOG_ALGS ; bankNum < HASH_COUNT ; bankNum++) {
	for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	    biosPcrs[bankNum][pcrNum ].hashAlg = TPM_ALG_NULL;
	}
    }
    for (*eventNum = 0 ; (rc == 0) && !done ; (*eventNum)++) {
	/* get the next event */
	char *eventString = NULL;
	if (rc == 0) {
	    rc = JS_Cmd_GetEvent(&eventString,	/* freed @2 */
				 *eventNum,
				 cmdJson);
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntries20Pass1: done, no event %u\n", *eventNum);  
		(*eventNum)--;	/* this event did not exist */
		done = TRUE;
	    } 
	}
	/* convert the event from a string to binary */
	unsigned char 	*eventBin = NULL;
	size_t 		eventLength;
	if ((rc == 0) && !done) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    eventString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries20Pass1: error scanning event %u\n", *eventNum);
	    }
	}
	if (*eventNum == 0) {
	    TCG_PCR_EVENT event;	/* TPM 1.2 agile event log entry, first event */
	    /* unmarshal the event from binary to structure */
	    if ((rc == 0) && !done) {
		if (vverbose) printf("processBiosEntries20Pass1: unmarshaling event %u\n",
				     *eventNum);
		unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
		uint32_t eventLengthPtr = eventLength;
		memset(event.event, 0, sizeof(event.event));	/* initialize to NUL terminated */
		rc = TSS_EVENT_Line_Unmarshal(&event, &eventBinPtr, &eventLengthPtr);
		if (rc != 0) {
		    printf("ERROR: processBiosEntries20Pass1: error unmarshaling event %u\n",
			   *eventNum);
		}
	    }
	}
	else {
	    TCG_PCR_EVENT2 event2;	/* TPM 2.0 hash agile event log entry */
	    /* unmarshal the event from binary to structure */
	    if ((rc == 0) && !done) {
		if (vverbose) printf("processBiosEntries20Pass1: unmarshaling event %u\n",
				     *eventNum);
		unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
		uint32_t eventLengthPtr = eventLength;
		memset(event2.event, 0, sizeof(event2.event));	/* initialize to NUL terminated */
		rc = TSS_EVENT2_Line_Unmarshal(&event2, &eventBinPtr, &eventLengthPtr);
		if (rc != 0) {
		    printf("ERROR: processBiosEntries20Pass1: error unmarshaling event %u\n",
			   *eventNum);
		}
	    }
	    /* the client should only send one hash algorithm */
	    if ((rc == 0) && !done) {
		if (event2.digests.count > BIOS_LOG_ALGS) {
		    printf("ERROR: processBiosEntries20Pass1: %u event log algorithms\n",
			   *eventNum);
		    rc = ACE_BAD_ALGORITHM;
		}
	    }
	    /* extend recalculated PCRs based on this event.  This function also does the PCR range
	       check. */
	    if ((rc == 0) && !done) {
		if (vverbose) printf("processBiosEntries20Pass1: Processing event %u PCR %u\n",
				     *eventNum, event2.pcrIndex);
		rc = TSS_EVENT2_PCR_Extend(biosPcrs, &event2);
		if (rc != 0) {
		    printf("ERROR: processBiosEntries20Pass1: error extending event %u\n",
			   *eventNum);
		    rc = ACE_EVENT;
		}
	    }
	    if ((rc == 0) && !done) {
		if (event2.pcrIndex < IMPLEMENTATION_PCR) {
		    if (vverbose) Array_Print(NULL, "processBiosEntries20Pass1: PCR digest", TRUE,
					      (uint8_t *)&biosPcrs[0][event2.pcrIndex].digest,
					      SHA256_DIGEST_SIZE);
		}
	    }
	}
	free(eventBin);			/* @1 */
	eventBin = NULL;
	free(eventString);		/* @2 */
	eventString = NULL;
    }
    if (rc == 0) {
	if (verbose) printf("INFO: processBiosEntries20Pass1: processed %u BIOS entries\n",
			    *eventNum);
    }
    /* if BIOS events were processed */
    for (pcrNum = 0 ; (rc == 0) && (*eventNum > 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	/* allocate the binary arrays */
	if (rc == 0) {
	    quotePcrsSha256Bin[pcrNum] = malloc(SHA256_DIGEST_SIZE);	/* freed by caller */
	    if (quotePcrsSha256Bin[pcrNum] == NULL) {
		printf("ERROR: processBiosEntries20Pass1: could not malloc %u bytes\n",
		       SHA256_DIGEST_SIZE);
		rc = ASE_OUT_OF_MEMORY;
	    }
	}
	/* copy the calculated values to the arrays */
	if (rc == 0) {
	    memcpy(quotePcrsSha256Bin[pcrNum],
	       (uint8_t *)&biosPcrs[0][pcrNum].digest, SHA256_DIGEST_SIZE);
	    if (vverbose) printf("processBiosEntries20Pass1: Calculated PCR %u\n", pcrNum);
	    if (vverbose) TSS_PrintAll("processBiosEntries20Pass1: Updated PCR",
				       (uint8_t *)quotePcrsSha256Bin[pcrNum],
				       SHA256_DIGEST_SIZE);
	}
    }
    /* if no BIOS events were processed, use previous PCRs */
    for (pcrNum = 0 ; (rc == 0) && (*eventNum == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (vverbose) printf("processBiosEntries: Scan SHA-256 PCR %u\n", pcrNum);
	/* convert previous quote PCRs to binary array */
	rc = Array_Scan(&quotePcrsSha256Bin[pcrNum],		/* freed by caller */
			&quotePcrsSha256BinLength[pcrNum],
			previousPcrs[pcrNum]);			/* previous uses SHA-256 bank */
	/* this should never occur since the server writes the DB */
	if (rc != 0) {
	    printf("ERROR: processBiosEntries20Pass1: PCRs invalid in server database\n");
	    rc = ASE_SQL_ERROR;
	}
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntries20Pass1: Use previous PCR %u\n", pcrNum);
	    if (vverbose) TSS_PrintAll("processBiosEntries20Pass1: Updated PCR",
				       (uint8_t *)quotePcrsSha256Bin[pcrNum],
				       SHA256_DIGEST_SIZE);
	}
    }    
    return rc;
}

#ifdef TPM_TPM12

/* processBiosEntries12Pass1() does the first pass through the BIOS log entries that the client
   sends with the quote.

   For each entry, it extends a PCR.  They start at all zero after a reboot.

   It returns when all client BIOS log entries have been processed.  Returns eventNum = 0 if no
   events were processed.

   if
   client returned bios event log
   reconstruct current bios pcrs from event log

   else
   use previous bios pcrs as current bios pcrs

   mallocs the sha1 bank.  Freed by caller.
*/

static uint32_t processBiosEntries12Pass1(unsigned int *eventNum,	/* events processed */
					  size_t quotePcrsSha1BinLength[],
					  uint8_t *quotePcrsSha1Bin[],  /* BIOS PCRs in quote, freed
									   by caller */
					  const char *previousPcrs[],
					  json_object *cmdJson)	/* client command, event log */
{
    uint32_t 		rc = 0;
    int			done = FALSE;
    uint32_t		pcrNum;
    TPMT_HA		biosPcrs[IMPLEMENTATION_PCR];		/* one bank, just sha1 */

    if (verbose) printf("INFO: processBiosEntries12Pass1: First pass, calculating BIOS PCRs\n");
    /* calculation starts with PCRs all zero */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	biosPcrs[pcrNum].hashAlg = TPM_ALG_SHA1;
	memset((uint8_t *)&biosPcrs[pcrNum].digest, 0, SHA1_DIGEST_SIZE);
    }
    /* iterate through all events */
    for (*eventNum = 0 ; (rc == 0) && !done ; (*eventNum)++ ) {
	/* get the next event */
	char *eventString = NULL;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&eventString,	/* freed @2 */
				 *eventNum,
				 cmdJson);
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntries12Pass1: done, no event %u\n", *eventNum);  
		(*eventNum)--;	/* this event did not exist, decrement because for loop increments */
		done = TRUE;
	    } 
	}
	/* convert the event from a string to binary */
	unsigned char *eventBin = NULL;
	size_t eventLength;
	if ((rc == 0) && !done) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    eventString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries12Pass1: error scanning event %u\n", *eventNum);
	    }
	}
	TCG_PCR_EVENT event;	/* TPM 1.2 event log entry */
	/* unmarshal the event from binary to structure */
	if ((rc == 0) && !done) {
	    if (vverbose) printf("processBiosEntries12Pass1: unmarshaling event %u\n", *eventNum);
	    unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
	    uint32_t eventLengthPtr = eventLength;
	    rc = TSS_EVENT_Line_Unmarshal(&event, &eventBinPtr, &eventLengthPtr);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries12Pass1: error unmarshaling event %u\n", *eventNum);
	    }
	}
	/* extend recalculated PCRs based on this event.  This function also does the PCR range
	   check. */
	if ((rc == 0) && !done) {
	    if (vverbose) printf("processBiosEntries12Pass1: Processing event %u PCR %u\n",
				 *eventNum, event.pcrIndex);
	    rc = TSS_EVENT_PCR_Extend(biosPcrs, &event);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries12Pass1: error extending event %u\n", *eventNum);
		rc = ACE_EVENT;
	    }
	}
	if ((rc == 0) && !done) {
	    if (event.pcrIndex < IMPLEMENTATION_PCR) {
		if (vverbose) Array_Print(NULL, "processBiosEntries12Pass1: PCR digest", TRUE,
					  (uint8_t *)&biosPcrs[event.pcrIndex].digest,
					  SHA1_DIGEST_SIZE);
	    }
	}
	free(eventBin);			/* @1 */
	eventBin = NULL;
	free(eventString);		/* @2 */
	eventString = NULL;
    }
    if (rc == 0) {
	if (verbose) printf("INFO: processBiosEntries12Pass1: processed %u BIOS entries\n",
			    *eventNum);
    }
    /* if BIOS events were processed */
    for (pcrNum = 0 ; (rc == 0) && (*eventNum > 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	/* allocate the binary arrays */
	if (rc == 0) {
	    quotePcrsSha1Bin[pcrNum] = malloc(SHA1_DIGEST_SIZE);	/* freed by caller */
	    if (quotePcrsSha1Bin[pcrNum] == NULL) {
		printf("ERROR: processBiosEntries12Pass1: could not malloc %u bytes\n",
		       SHA1_DIGEST_SIZE);
		rc = ASE_OUT_OF_MEMORY;
	    }
	}
	/* copy the calculated values to the arrays */
	if (rc == 0) {
	    memcpy(quotePcrsSha1Bin[pcrNum],
		   (uint8_t *)&biosPcrs[pcrNum].digest, SHA1_DIGEST_SIZE);
	    if (vverbose) printf("processBiosEntries12Pass1: Calculated PCR %u\n", pcrNum);
	    if (vverbose) TSS_PrintAll("processBiosEntries12Pass1: Updated PCR",
				       (uint8_t *)quotePcrsSha1Bin[pcrNum],
				       SHA1_DIGEST_SIZE);
	}
    }
    /* if no BIOS events were processed, use previous PCRs */
    for (pcrNum = 0 ; (rc == 0) && (*eventNum == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (vverbose) printf("processBiosEntries12Pass1: Scan SHA-1 PCR %u\n", pcrNum);
	/* convert previous quote PCRs to binary array */
	rc = Array_Scan(&quotePcrsSha1Bin[pcrNum],		/* freed by caller */
			&quotePcrsSha1BinLength[pcrNum],
			previousPcrs[pcrNum]);		/* DB always uses sha256 column */
	if (rc != 0) {
	    printf("ERROR: processBiosEntries12Pass1: PCRs invalid in server database\n");
	    rc = ASE_SQL_ERROR;
	}
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntries12Pass1: Use previous PCR %u\n", pcrNum);
	    if (vverbose) TSS_PrintAll("processBiosEntries12Pass1: Updated PCR",
				       (uint8_t *)quotePcrsSha1Bin[pcrNum],
				       SHA1_DIGEST_SIZE);
	}
    }    
    return rc;
}

#endif /* TPM_TPM12 */

/* processImaEntries20Pass1() processes each IMA entry, calculates PCR 10, and then checks the
   resulting PCRs against the quote PCR digest.

   On input, firstImaEventNum is the next event to be processed.

   On output, nextImaEventNum is the event number to be processed in the next pass.  I.e., the total
   number processed since boot, the next event in the incremental log, and the next event to be
   processed in the next quote and incremental log.

   if client returned IMA log
   if starts at zero
   set IMA PCR to zero

   else
   set IMA PCR from previous ima pcrs

   for each IMA event
   calculate PCR value
   check pcr digest against stored pcrs

   Returns quotePcrsSha256Bin as the reconstructed quote PCRs.  This is either the input array (for
   a first attestation after a boot) or a freed / malloced array (for an incremental log).
   
*/

static uint32_t processImaEntries20Pass1(unsigned int *logVerified,
					 unsigned int *nextImaEventNum,
					 unsigned int firstImaEventNum,
					 size_t quotePcrsSha256BinLength[],
					 uint8_t *quotePcrsSha256Bin[], /* IMA PCRs in quote, freed
									   by caller */
					 const char *previousPcrs[],
					 TPMS_ATTEST *tpmsAttest,	/* quote result */
					 json_object *cmdJson)		/* client command */
{
    uint32_t  		rc = 0;
    TPML_PCR_SELECTION	pcrSelection;
    unsigned int 	imaEventNum = firstImaEventNum; /* iterator, starting event */
    int			first = TRUE;			/* first time through loop */
    int 		done = FALSE;
    int			eof = FALSE;			/* flag, no more IMA events */

    *logVerified = FALSE;

    if (vverbose) printf("processImaEntries20Pass1: First imaEventNum %u\n", firstImaEventNum);
    /* get the first IMA event number to be processed */
    if (rc == 0) {
	/* if the client sent an incremental log, start at previous PCR */
	if (firstImaEventNum > 0) {
	    /* convert previous quote IMA PCR to binary array */
	    free(quotePcrsSha256Bin[TPM_IMA_PCR]);
	    quotePcrsSha256Bin[TPM_IMA_PCR] = NULL;
	    rc = Array_Scan(&quotePcrsSha256Bin[TPM_IMA_PCR],	/* freed by caller */
			    &quotePcrsSha256BinLength[TPM_IMA_PCR],
			    previousPcrs[TPM_IMA_PCR]);
	    if (rc != 0) {
		printf("ERROR: processImaEntries20Pass1: PCRs invalid in server database\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	/* client sent entries starting at entry zero */
	else {		/* if new, not incremental log, start at zero */
	    memset(quotePcrsSha256Bin[TPM_IMA_PCR], 0, TPM_SHA256_SIZE);
	}
    }
    if (rc == 0) {
	uint32_t pcrNum;
	for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	    if (vverbose) printf("processImaEntries20Pass1: Starting PCR %u\n", pcrNum);
	    if (vverbose) TSS_PrintAll("processImaEntries20Pass1: PCR",
				       (uint8_t *)quotePcrsSha256Bin[pcrNum],
				       SHA256_DIGEST_SIZE);
	}
    }
    while ((rc == 0) && !(*logVerified) && !done) {
	unsigned char pcrBinStream[HASH_COUNT * IMPLEMENTATION_PCR * MAX_DIGEST_SIZE];
	size_t pcrBinStreamSize = 0;

	/* calculate PCR digest from quotePcrsBin */
	if (rc == 0) {
	    makePcrSelect20(&pcrSelection);	/* server PCR selection */
	    if (rc == 0) {
		rc = makePcrStream20(pcrBinStream,
				     &pcrBinStreamSize,
				     quotePcrsSha256Bin,
				     &pcrSelection);
	    }
	}
	/* construct the client pcrDigest */
	TPMT_HA digest;
	if (rc == 0) {
#if 0
	    if (vverbose) Array_Print(NULL, "processImaEntries20Pass1: PCR stream", TRUE,
				      pcrBinStream, pcrBinStreamSize);
#endif
	    digest.hashAlg = TPM_ALG_SHA256;	/* algorithm of signing key */
	    rc = TSS_Hash_Generate(&digest,
				   pcrBinStreamSize, pcrBinStream,
				   0, NULL);
	}
	/* validate against pcrDigest in quoted, size and contents */
	if (rc == 0) {
	    if (tpmsAttest->attested.quote.pcrDigest.t.size != SHA256_DIGEST_SIZE) {
		printf("ERROR: processImaEntries20Pass1: quoted PCR digest size %u not supported\n",
		       tpmsAttest->attested.quote.pcrDigest.t.size);  
		rc = ACE_DIGEST_LENGTH;
	    }
	}
	if (rc == 0) {
	    int irc = memcmp(tpmsAttest->attested.quote.pcrDigest.t.buffer,
			     (uint8_t *)&digest.digest, SHA256_DIGEST_SIZE);
	    if (vverbose) Array_Print(NULL, "processImaEntries20Pass1: Digest from quote", TRUE,
				      tpmsAttest->attested.quote.pcrDigest.t.buffer,
				      SHA256_DIGEST_SIZE);
	    if (vverbose) Array_Print(NULL, "processImaEntries20Pass1: Digest from PCRs", TRUE,
				      (uint8_t *)&digest.digest,
				      SHA256_DIGEST_SIZE);
	    if (irc == 0) {
		*logVerified = TRUE;
	    }
	}
	if (rc == 0) {
	    /* if PCRs matches quote */
	    if (*logVerified) {
		if (first) {	/* first pass, haven't processed any new entries yet */
		    if (vverbose) printf("processImaEntries20Pass1: Done before IMA events\n");
		    *nextImaEventNum = firstImaEventNum; 	/* return same value */
		}
		if (!first) {
		    if (vverbose) printf("processImaEntries20Pass1: Done at IMA event number %u\n",
					 imaEventNum);
		    *nextImaEventNum = imaEventNum + 1;		/* return next value */
		}
		done = TRUE;
	    }
	    else {
		if (!first) {
		    imaEventNum++;	/* not first pass, process the next event */
		}
	    }
	    first = FALSE;
	}
	/* if more to process, get the next IMA event and update the IMA PCR quotePcrsSha256Bin */
	if (!done) {
	    char *eventString = NULL;
	    if (rc == 0) {
		/* read the next IMA event */
		if (vverbose) printf("processImaEntries20Pass1: Processing IMA event %u\n",
				     imaEventNum);
		eof = JS_Cmd_GetImaEvent(&eventString,	/* freed @3 */
					 imaEventNum,
					 cmdJson);
		/* If there is no next event, done walking measurement list.  This is not a json
		   error, because the server does not know in advance how many entries the client
		   will send.  However, since IMA PCR did not match, there is an error to be
		   processed below.  */
		if (eof) {
		    done = TRUE;
		    if (vverbose) printf("processImaEntries20Pass1: done, no event %u\n",
					 imaEventNum);
		}
	    }
	    unsigned char *event = NULL;
	    size_t eventLength;
	    /* convert the event from a string to binary */
	    if ((rc == 0) && !done) {
		rc = Array_Scan(&event,			/* freed @2 */
				&eventLength,
				eventString);
		if (rc != 0) {
		    printf("ERROR: processImaEntries20Pass1: error scanning event %u\n",
			   imaEventNum);
		}
	    }
	    free(eventString);				/* @3 */
	    eventString = NULL;
	    unsigned char *eventFree = event;	/* because IMA_Event_ReadBuffer moves the buffer */
	    ImaEvent imaEvent;
	    IMA_Event_Init(&imaEvent);		/* so the first free works */
	    /* unmarshal the event */
	    if ((rc == 0) && !done) {
		if (vverbose) printf("processImaEntries20Pass1: unmarshaling event %u\n",
				     imaEventNum);
		int endOfBuffer;	/* unused */
		rc = IMA_Event_ReadBuffer(&imaEvent,		/* freed @1 */
					  &eventLength,
					  &event,
					  &endOfBuffer,
					  FALSE,	/* client sends to server in HBO */
					  TRUE);	/* parse template data now so errors will
							   not occur in the 2nd pass */
		if (rc != 0) {
		    printf("ERROR: processImaEntries20Pass1: error unmarshaling event %u\n",
			   imaEventNum);
		}
	    }
	    if ((rc == 0) && !done) {
		if (vverbose) IMA_Event_Trace(&imaEvent, FALSE);
	    }
	    /* extend the IMA event */
	    TPMT_HA imapcr;
	    if ((rc == 0) && !done) {
		memcpy(&imapcr.digest, quotePcrsSha256Bin[TPM_IMA_PCR], TPM_SHA256_SIZE);
		
		rc = IMA_Extend(&imapcr, &imaEvent, TPM_ALG_SHA256);
		if (rc != 0) {
		    printf("ERROR: processImaEntries20Pass1: error extending event %u\n",
			   imaEventNum);
		}
	    }
	    /* trace the updated IMA PCR value */
	    if ((rc == 0) && !done) {
		memcpy(quotePcrsSha256Bin[TPM_IMA_PCR], &imapcr.digest, TPM_SHA256_SIZE);
		if (vverbose) TSS_PrintAll("processImaEntries20Pass1: Updated IMA PCR",
					   (uint8_t *)quotePcrsSha256Bin[TPM_IMA_PCR],
					   SHA256_DIGEST_SIZE);
	    }
	    IMA_Event_Free(&imaEvent);	/* @1 */
	    free(eventFree);		/* @2 */
	    event = NULL;
	}
    }
    return rc;
}

#ifdef TPM_TPM12

/* processImaEntries12Pass1() processes each IMA entry, calculates PCR 10, and then checks the
   resulting PCRs against the quote PCR digest.

   On input, firstImaEventNum is the next event to be processed.

   On output, nextImaEventNum is the event number to be processed in the next pass.  I.e., the total
   number processed since boot, the next event in the incremental log, and the next event to be
   processed in the next quote and incremental log.

   Returns quotePcrsSha256Bin as the reconstructed quote PCRs.  This is either the input array (for
   a first attestation after a boot) or a freed / malloced array (for an incremental log).

*/

static uint32_t processImaEntries12Pass1(unsigned int *logVerified,	/* bool, PCRs matched */
					 unsigned int *nextImaEventNum,
					 unsigned int firstImaEventNum,
					 size_t quotePcrsSha1BinLength[],
					 uint8_t *quotePcrsSha1Bin[], 	/* IMA PCRs in quote, freed
									   by caller */
					 const char *previousPcrs[],
					 TPM_PCR_INFO_SHORT *pcrInfoShort,
					 json_object *cmdJson)		/* client command */
{
    uint32_t  		rc = 0;
    unsigned int 	imaEventNum = firstImaEventNum; /* iterator, starting event */
    int			first = TRUE;			/* first time through loop */
    int 		done = FALSE;
    int			eof = FALSE;			/* flag, no more IMA events */

    *logVerified = FALSE;

    if (vverbose) printf("processImaEntries12Pass1: First imaEventNum %u\n", firstImaEventNum);
    /* get the first IMA event number to be processed */
    if (rc == 0) {
	/* if the client sent an incremental log, start at previous PCR */
	if (firstImaEventNum > 0) {
	    /* convert previous quote IMA PCR to binary array */
	    free(quotePcrsSha1Bin[TPM_IMA_PCR]);
	    quotePcrsSha1Bin[TPM_IMA_PCR] = NULL;
	    rc = Array_Scan(&quotePcrsSha1Bin[TPM_IMA_PCR],	/* freed by caller */
			    &quotePcrsSha1BinLength[TPM_IMA_PCR],
			    previousPcrs[TPM_IMA_PCR]);
	    if (rc != 0) {
		printf("ERROR: processImaEntries12Pass1: PCRs invalid in server database\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	/* client sent entries starting at entry zero */
	else {
	    memset(quotePcrsSha1Bin[TPM_IMA_PCR], 0, TPM_SHA1_SIZE);
	}
    }
    if (rc == 0) {
	uint32_t pcrNum;
	for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	    if (vverbose) printf("processImaEntries12Pass1: Starting PCR %u\n", pcrNum);
	    if (vverbose) TSS_PrintAll("processImaEntries12Pass1: PCR",
				       (uint8_t *)quotePcrsSha1Bin[pcrNum],
				       SHA1_DIGEST_SIZE);
	}
    }
    while ((rc == 0) && !(*logVerified) && !done) {
	unsigned char pcrBinStream[sizeof(TPML_PCR_SELECTION) +
				   HASH_COUNT * IMPLEMENTATION_PCR * MAX_DIGEST_SIZE];
	uint16_t pcrBinStreamSize = 0;

	/* calculate PCR digest from quotePcrsBin */
	if (rc == 0) {
	    rc = makePcrStream12(pcrBinStream,
				 &pcrBinStreamSize,
				 quotePcrsSha1Bin);
	}
	/* construct the client pcrDigest */
	TPMT_HA digest;
	if (rc == 0) {
#if 0
	    if (vverbose) Array_Print(NULL, "processImaEntries12Pass1: PCR stream", TRUE,
				      pcrBinStream, pcrBinStreamSize);
#endif
	    digest.hashAlg = TPM_ALG_SHA1;	/* algorithm of signing key */
	    rc = TSS_Hash_Generate(&digest,
				   pcrBinStreamSize, pcrBinStream,
				   0, NULL);
	}
	/* validate against pcrDigest in quoted */
	if (rc == 0) {
	    int irc = memcmp(pcrInfoShort->digestAtRelease,
			     (uint8_t *)&digest.digest, SHA1_DIGEST_SIZE);
	    if (vverbose) Array_Print(NULL, "processImaEntries12Pass1: Digest from quote", TRUE,
				      pcrInfoShort->digestAtRelease,
				      SHA1_DIGEST_SIZE);
	    if (vverbose) Array_Print(NULL, "processImaEntries12Pass1: Digest from PCRs", TRUE,
				      (uint8_t *)&digest.digest,
				      SHA1_DIGEST_SIZE);
	    if (irc == 0) {
		*logVerified = TRUE;
	    }
	}
	if (rc == 0) {
	    /* if PCRs matches quote */
	    if (*logVerified) {
		if (first) {	/* first pass, haven't processed any new entries yet */
		    if (vverbose) printf("processImaEntries12Pass1: Done before IMA events\n");
		    *nextImaEventNum = firstImaEventNum; 	/* return same value */
		}
		if (!first) {
		    if (vverbose) printf("processImaEntries12Pass1: Done at IMA event number %u\n",
					 imaEventNum);
		    *nextImaEventNum = imaEventNum + 1;		/* return next value */
		}
		done = TRUE;
	    }
	    else {
		if (!first) {
		    imaEventNum++;	/* not first pass, process the next event */
		}
	    }
	    first = FALSE;
	}
	/* if more to process, get the next IMA event and update the IMA PCR quotePcrsSha1Bin */
	if (!done) {
	    char *eventString = NULL;
	    /* read the next IMA event */
	    if (vverbose) printf("processImaEntries12Pass1: Process IMA event %u\n",
				 imaEventNum);
	    if (rc == 0) {
		eof = JS_Cmd_GetImaEvent(&eventString,	/* freed @3 */
					 imaEventNum,
					 cmdJson);
		/* If there is no next event, done walking measurement list.  This is not a json
		   error, because the server does not know in advance how many entries the client
		   will send.  However, since IMA PCR did not match, there is an error to be
		   processed below.  */
		if (eof) {
		    done = TRUE;
		    if (vverbose) printf("processImaEntries12Pass1: done, no event %u\n",
					 imaEventNum);
		} 
	    }
	    unsigned char *event = NULL;
	    size_t eventLength;
	    /* convert the event from a string to binary */
	    if ((rc == 0) && !done) {
		rc = Array_Scan(&event,			/* freed @2 */
				&eventLength,
				eventString);
		if (rc != 0) {
		    printf("ERROR: processImaEntries12Pass1: error scanning event %u\n",
			   imaEventNum);
		}
	    }
	    free(eventString);	/* @3 */
	    eventString = NULL;
	    unsigned char *eventFree = event;	/* because IMA_Event_ReadBuffer moves the buffer */
	    ImaEvent imaEvent;
	    IMA_Event_Init(&imaEvent);		/* so the first free works */
	    /* unmarshal the event */
	    if ((rc == 0) && !done) {
		if (vverbose) printf("processImaEntries12Pass1: unmarshaling event %u\n",
				     imaEventNum);
		int endOfBuffer;	/* unused */
		rc = IMA_Event_ReadBuffer(&imaEvent,		/* freed @1 */
					  &eventLength,
					  &event,
					  &endOfBuffer,
					  FALSE,	/* client sends to server in HBO */
					  TRUE);	/* parse template data now so errors will
							   not occur in the 2nd pass */
		if (rc != 0) {
		    printf("ERROR: processImaEntries12Pass1: error unmarshaling event %u\n",
			   imaEventNum);
		}
	    }
	    if ((rc == 0) && !done) {
		if (vverbose) IMA_Event_Trace(&imaEvent, FALSE);
	    }
	    /* extend the IMA event */
	    TPMT_HA imapcr;
	    if ((rc == 0) && !done) {
		memcpy(&imapcr.digest, quotePcrsSha1Bin[TPM_IMA_PCR], TPM_SHA1_SIZE);
		
		rc = IMA_Extend(&imapcr, &imaEvent, TPM_ALG_SHA1);
		if (rc != 0) {
		    printf("ERROR: processImaEntries12Pass1: error extending event %u\n",
			   imaEventNum);
		}
	    }
	    /* trace the updated IMA PCR value */
	    if ((rc == 0) && !done) {
		memcpy(quotePcrsSha1Bin[TPM_IMA_PCR], &imapcr.digest, TPM_SHA1_SIZE);
		if (vverbose) TSS_PrintAll("processImaEntries12Pass1: Updated IMA PCR",
					   (uint8_t *)quotePcrsSha1Bin[TPM_IMA_PCR],
					   SHA1_DIGEST_SIZE);
	    }
	    IMA_Event_Free(&imaEvent);	/* @1 */
	    free(eventFree);		/* @2 */
	    event = NULL;
	}
    }
    return rc;
}

#endif /* TPM_TPM12 */


/* verifyQuoteSignature() verifies the TPM 2.0 quote signature (tpmtSignature) against the message
   (quotedBin) using the public key (akCertificatePem).

   Handles RSA and ECC signatures, SHA-256.
*/

static uint32_t verifyQuoteSignature(unsigned int 	*quoteVerified,		/* result */
				     unsigned char 	*quotedBin,		/* message */
				     size_t 		quotedBinSize,		/* message size */
				     const char 	*akCertificatePem,	/* public key */
				     TPMT_SIGNATURE 	*tpmtSignature)		/* signature */
{
    uint32_t 	rc = 0;
 
    /* SHA-256 hash the quoted */
    TPMT_HA digest;
    if (rc == 0) {
	if (verbose) printf("INFO: verifyQuoteSignature: Verifying quote signature\n");
	if (vverbose) printf("verifyQuoteSignature: quotedBinSize %lu\n", quotedBinSize);
	if (vverbose) Array_Print(NULL, "verifyQuoteSignature: quotedBin", TRUE,
				  quotedBin, quotedBinSize);
	digest.hashAlg = TPM_ALG_SHA256;
	rc = TSS_Hash_Generate(&digest,
			       quotedBinSize, quotedBin,
			       0, NULL);
    }
    if (rc == 0) {
	if (vverbose) Array_Print(NULL, "verifyQuoteSignature: quoteMessage", TRUE,
				  (uint8_t *)&digest.digest, SHA256_DIGEST_SIZE);
	if (vverbose) Array_Print(NULL, "verifyQuoteSignature: signature", TRUE,
				  tpmtSignature->signature.rsassa.sig.t.buffer,
				  tpmtSignature->signature.rsassa.sig.t.size);
    }
    X509 		*x509 = NULL;		/* public key */
    /* convert the quote verification PEM certificate to X509 */
    if (rc == 0) {
	rc = convertPemMemToX509(&x509,			/* freed @1 */
				 akCertificatePem);
    }
    if (rc == 0) {
	if (tpmtSignature->sigAlg == TPM_ALG_RSASSA) {
	    if (rc == 0) {
		rc = verifyQuoteSignatureRSA(quoteVerified,	/* result */
					     TRUE,		/* sha256 */
					     &digest,
					     x509,	    	/* public key */
					     tpmtSignature);	/* signature */
	    }
	}
	else if (tpmtSignature->sigAlg == TPM_ALG_ECDSA) {
	    if (rc == 0) {
	       rc = verifyQuoteSignatureECC(quoteVerified,		/* result */
					    &digest,
					    x509,			/* public key */
					    tpmtSignature);		/* signature */
	   }
       }
       else {
	   if (rc == 0) {
	       printf("ERROR: verifyQuoteSignature: Invalid signature algorithm \n");
	   }
       }
    }
    if (x509 != NULL) {
	X509_free(x509);		/* @1 */
    }
   return rc;
}

#ifdef TPM_TPM12

/* verifyQuoteSignature12() verifies the TPM 1.2 quote signature against the message using the
   public key (akCertificatePem).

   Handles RSA and SHA-1.
*/

static uint32_t verifyQuoteSignature12(unsigned int 	*quoteVerified,		/* result */
				       const char 	*nonceServerString,
				       unsigned char 	*pcrDataBin,
				       size_t 		pcrDataBinSize,
				       unsigned char 	*versionInfoBin,
				       size_t 		versionInfoBinSize,
				       const char 	*akCertificatePem,	/* public key */
				       unsigned char 	*signatureBin,		/* signature */
				       size_t 		signatureBinSize)
{
    uint32_t 		rc = 0;
    unsigned char 	*nonceServerBin = NULL;
    size_t 		nonceServerBinSize;
    
    if (rc == 0) {
	rc = Array_Scan(&nonceServerBin,	/* output binary, freed @1 */
			&nonceServerBinSize,
			nonceServerString);	/* input string */
    }
    /* convert the pcrData to the TPM_PCR_INFO_SHORT */
    TPM_PCR_INFO_SHORT pcrData;
    if (rc == 0) {
	uint8_t *buffer = pcrDataBin;
	uint32_t size = pcrDataBinSize;
	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshalu(&pcrData, &buffer, &size);
    }
    TPM_QUOTE_INFO2	q1;
    uint8_t		*q1Buffer = NULL;
    uint16_t		q1Written;
    /* construct marshaled TPM_QUOTE_INFO2 */
    if (rc == 0) {
	q1.tag = TPM_TAG_QUOTE_INFO2;
	memcpy(&q1.fixed, "QUT2", 4);
	memcpy(&(q1.externalData), nonceServerBin, TPM_NONCE_SIZE);
	q1.infoShort = pcrData;
	rc = TSS_Structure_Marshal(&q1Buffer,	/* freed @2 */
				   &q1Written,
				   &q1,
				   (MarshalFunction_t)TSS_TPM_QUOTE_INFO2_Marshalu);
    }
    /* recalculate the signed hash */
    TPMT_HA		q1Digest;
    if (rc == 0) {
	q1Digest.hashAlg = TPM_ALG_SHA1;
	rc = TSS_Hash_Generate(&q1Digest,	
			       q1Written, q1Buffer,			/* TPM_QUOTE_INFO2 */
			       versionInfoBinSize, versionInfoBin,	/* TPM_CAP_VERSION_INFO */
			       0, NULL);
    }
    if (rc == 0) {
	if (vverbose) Array_Print(NULL, "verifyQuoteSignature12: quote digest", TRUE,
				  (uint8_t *)&q1Digest.digest, SHA1_DIGEST_SIZE);
	if (vverbose) Array_Print(NULL, "verifyQuoteSignature12: signature", TRUE,
				  signatureBin, signatureBinSize);
    }
    X509 		*x509 = NULL;		/* public key */
    /* convert the quote verification PEM certificate to X509 */
    if (rc == 0) {
	rc = convertPemMemToX509(&x509,			/* freed @3 */
				 akCertificatePem);
    }
    if (rc == 0) {
	rc = verifyQuoteSignatureRSA(quoteVerified,		/* result */
				     FALSE,			/* sha1 */
				     &q1Digest,			/* message */
				     x509,			/* public key */
				     signatureBinSize,
				     signatureBin);		/* signature */
    }
    free(nonceServerBin);		/* @1 */
    free(q1Buffer);			/* @2 */
    if (x509 != NULL) {
	X509_free(x509);		/* @3 */
    }
    return rc;
}

#endif /* TPM_TPM12 */

/* verifyQuoteSignatureRSA() verifies the quote signature against the message
   using the public key (akCertificatePem).

*/

static uint32_t verifyQuoteSignatureRSA(unsigned int 	*quoteVerified,		/* result */
					int 		sha256,			/* boolean */
					TPMT_HA 	*digest,		/* message */
					X509 		*x509,			/* public key */
					TPMT_SIGNATURE 	*tpmtSignature)		/* signature */
{
    uint32_t 	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;

    if (rc == 0) {
	evpPkey = X509_get_pubkey(x509);	/* freed @1 */
	if (evpPkey == NULL) {
	    printf("ERROR: verifyQuoteSignatureRSA: X509_get_pubkey failed\n");  
	    rc = ACE_OSSL_X509;
	}
    }
    if (rc == 0) {
	rc =  verifyRSASignatureFromEvpPubKey((uint8_t *)&digest->digest,
					      (sha256 ? SHA256_DIGEST_SIZE : SHA1_DIGEST_SIZE),
					      tpmtSignature,
					      (sha256 ? TPM_ALG_SHA256 : TPM_ALG_SHA),
					      evpPkey);
	      if (rc != 0) {
		  rc = ACE_QUOTE_SIGNATURE;	/* skip reset of the tests */
		  *quoteVerified = FALSE;	/* remains false */
		  printf("ERROR: verifyQuoteSignatureRSA: Signature verification failed\n");
	      }
	      else {
		  *quoteVerified = TRUE;	/* tentative */
		  if (verbose) printf("INFO: verifyQuoteSignatureRSA: quote signature verified\n");
	      }
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }

    return rc;
}

/* verifyQuoteSignatureECC() verifies the quote signature (tpmtSignature) against the message
   (quotedBin) using the public key (akCertificatePem).

*/

static uint32_t verifyQuoteSignatureECC(unsigned int 	*quoteVerified,		/* result */
					TPMT_HA 	*digest,
					X509 		*x509,			/* public key */
					TPMT_SIGNATURE 	*tpmtSignature)		/* signature */
{
    uint32_t 	rc = 0;
    EVP_PKEY *evpPkey = NULL;

    if (rc == 0) {
	evpPkey = X509_get_pubkey(x509);	/* freed @1 */
	if (evpPkey == NULL) {
	    printf("ERROR: verifyQuoteSignatureECC: X509_get_pubkey failed\n");  
	    rc = ACE_OSSL_X509;
	}
    }
    if (rc == 0) {
	rc = verifyEcSignatureFromEvpPubKey((uint8_t *)&digest->digest,
					    SHA256_DIGEST_SIZE,
					    tpmtSignature,
					    evpPkey);
	if (rc != 0) {
	    rc = ACE_QUOTE_SIGNATURE;	/* skip reset of the tests */
	    *quoteVerified = FALSE;	/* remains false */
	    printf("ERROR: verifyQuoteSignatureECC: Signature verification failed\n");
	}
	else {
	    *quoteVerified = TRUE;	/* tentative */
	    if (verbose) printf("INFO: verifyQuoteSignatureECC: quote signature verified\n");
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

/* verifyQuoteNonce() verifies the client quote nonce against the nonce stored by the server.

*/

static uint32_t verifyQuoteNonce(unsigned int 	*quoteVerified,		/* boolean result */
				 const char 	*nonceServerString,	/* server */
				 TPMS_ATTEST 	*tpmsAttest)		/* client */
{
    uint32_t 	rc = 0;
    unsigned char 	*nonceServerBin = NULL;
    size_t 		nonceServerBinSize;

    /* convert the server nonce to binary, server error since the nonce should have been inserted
       correctly */
    if (rc == 0) {
	if (verbose) printf("INFO: verifyQuoteNonce: Verifying nonce\n");
	rc = Array_Scan(&nonceServerBin,	/* output binary, freed @1 */
			&nonceServerBinSize,
			nonceServerString);	/* input string */
    }
    /* check nonce sizes */
    if (rc == 0) {
	if (nonceServerBinSize != tpmsAttest->extraData.t.size) {
	    *quoteVerified = FALSE;	/* quote nonce */
	    printf("ERROR: verifyQuoteNonce: nonce size mismatch, server %lu client %u\n",
		   nonceServerBinSize, tpmsAttest->extraData.t.size);
	}
    }
    /* compare to the server nonce to the client nonce from the quoted */
    if (rc == 0) {
	if (memcmp(nonceServerBin, &tpmsAttest->extraData.t.buffer, nonceServerBinSize) != 0) {
	    *quoteVerified = FALSE;	/* quote nonce */
	    printf("ERROR: verifyQuoteNonce: client nonce does not match server database\n");  
	}
	else {
	    *quoteVerified = TRUE;
	    if (verbose) printf("INFO: verifyQuoteNonce: client nonce matches server database\n");  
	}
    }
    free(nonceServerBin);		/* @1 */
    return rc;
}

/* processQuoteResults() updates the attestdb with the quote portion of the json packet and the
   boolean quote verified result */

static uint32_t processQuoteResults(json_object 	*cmdJson,
				    unsigned int 	quoteVerified,
				    const char 		*attestLogId,
				    MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    int 	irc;
    char 	query[QUERY_LENGTH_MAX];

    const char *command = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&command, "command", ACS_JSON_COMMAND_MAX, cmdJson);
    }
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    const char *quoted = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&quoted , "quoted", ACS_JSON_QUOTED_MAX, cmdJson);
    }
    const char *signature = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&signature , "signature", ACS_JSON_SIGNATURE_MAX, cmdJson);
    }
    if (rc == 0) {
	irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update attestlog set quote = '\n{\n"
			   "  \"command\":\"quote\",\n"
			   "  \"hostname\":\"%s\",\n"
			   "  \"quoted\":\"%s\",\n"
			   "  \"signature\":\"%s\"\n"
			   "}'"
			   " where id = '%s'",
			   hostname, quoted, signature, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processQuoteResults: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    if (rc == 0) {
	irc = snprintf(query, QUERY_LENGTH_MAX,
		       "update attestlog set quoteverified = '%u' where id = '%s'",
		       quoteVerified, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processQuoteResults: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    return rc;
}

#ifdef TPM_TPM12

/* processQuoteResults12() updates the attestdb with the quote portion of the json packet and the
   boolean quote verified result */

static uint32_t processQuoteResults12(json_object 	*cmdJson,
				      unsigned int 	quoteVerified,
				      const char 	*attestLogId,
				      MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    int 	irc;
    char 	query[QUERY_LENGTH_MAX];

    const char *command = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&command, "command", ACS_JSON_COMMAND_MAX, cmdJson);
    }
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    const char *pcrdata = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&pcrdata, "pcrdata", ACS_JSON_PCRDATA_MAX, cmdJson);
    }
    const char *versioninfo = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&versioninfo, "versioninfo", ACS_JSON_VERSIONINFO_MAX, cmdJson);
    }
    const char *signature = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&signature , "signature", ACS_JSON_SIGNATURE_MAX, cmdJson);
    }
    if (rc == 0) {
	irc = snprintf(query, QUERY_LENGTH_MAX,
		       "update attestlog set quote = '\n{\n"
		       "  \"command\":\"quote12\",\n"
		       "  \"hostname\":\"%s\",\n"
		       "  \"pcrdata\":\"%s\",\n"
		       "  \"versioninfo\":\"%s\",\n"
		       "  \"signature\":\"%s\"\n"
		       "}'"
		       " where id = '%s'",
		       hostname, pcrdata, versioninfo, signature, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processQuoteResults12: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    if (rc == 0) {
	irc = snprintf(query, QUERY_LENGTH_MAX,
		       "update attestlog set quoteverified = '%u' where id = '%s'",
		       quoteVerified, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processQuoteResults12: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    return rc;
}

#endif /* TPM_TPM12 */

/* processBiosLogResults() updates the attestdb with:

   the boolean log verified result
   the number of BIOS events processed
*/

uint32_t processBiosLogResults(unsigned int 	logVerified,	/* PCR digest matches event logs */
			   unsigned int 	eventNum,	/* BIOS events processed */
			   const char 		*attestLogId,
			   MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    int 	irc;
    char 	query[QUERY_LENGTH_MAX];

    if (vverbose) printf("processBiosLogResults: logVerified %u eventNum %u\n",
			 logVerified, eventNum);
    if (rc == 0) {
	irc = snprintf(query, QUERY_LENGTH_MAX,
		       "update attestlog set logverified = '%u' where id = '%s'",
		       logVerified, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processBiosLogResults: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    if (logVerified) {
	if (rc == 0) {
	    irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update attestlog set logentries = '%u' "
			   "where id = '%s'",
			   eventNum, attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processBiosLogResults: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    return rc;
}

/* processImaLogResults() updates the attestdb:

   with the boolean log verified result
   the number of IMA events processed
*/

uint32_t processImaLogResults(unsigned int 	logVerified,		/* PCR digest matches event logs */
			      unsigned int 	nextImaEventNum,	/* next IMA event to be processed */
			      const char 	*attestLogId,
			      MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    int 	irc;
    char 	query[QUERY_LENGTH_MAX];

    if (vverbose) printf("processImaLogResults: logVerified %u imaEventNum %u\n",
			 logVerified, nextImaEventNum);
    if (rc == 0) {
	irc = snprintf(query, QUERY_LENGTH_MAX,
		       "update attestlog set imaver = '%u' where id = '%s'",
		       logVerified, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processImaLogResults: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    if (logVerified) {
	if (rc == 0) {
	    /* lastImaEventNum is the last event processed.  imaEventNum-1 is the number of events
	       processed */
	    irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update attestlog set imaevents  = '%u' "
			   "where id = '%s'",
			   nextImaEventNum, attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processImaLogResults: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    return rc;
}

static unsigned updateImaState(unsigned int 	nextImaEventNum, /* next IMA event number
								    to be processed */
			       char		*imaPcrString,
			       const char 	*machineId,
			       MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    char query[QUERY_LENGTH_MAX];
    /* update the machines table */
    if (rc == 0) {
	/* if the IMA log verified, update the imaevents to the next event for an incremental update
	   and the imapcr to the current quote value */
	int irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update machines set imaevents = '%u', imapcr = '%s' where id = '%s'",
			   nextImaEventNum,		/* next event to be processed */
			   imaPcrString, machineId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processImaEntry: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    return rc;
}

/* processQuotePCRs() updates the attestdb with the reconstructed and verified PCR values

   NOTE: There was originally support for mixed algorithms.  Now, the pcrnnsha256 DB field is used
   exclusively.  It should be renamed.
 */

static uint32_t processQuotePCRs(char 		*quotePcrsString[],
				 const char 	*attestLogId,
				 MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    int 	irc;
    uint32_t	pcrNum;
    char 	query[QUERY_LENGTH_MAX];

    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (rc == 0) {
	    irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update attestlog set pcr%02usha256 = '%s' where id = '%s'",
			   pcrNum, quotePcrsString[pcrNum], attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processQuotePCRs: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    return rc;
}

/* processQuoteWhiteList() handles the BIOS PCR white list.

   The first time through, the machines DB PCRs are null.  There is no BIOS PCR white list.  The
   current attestlog DB PCRs are copied to the machines DB as the white list. pcrschanged is not
   updated.

   After the first time, the PCRs are compared, and the pcrschanged flag is updated.
*/

static uint32_t processQuoteWhiteList(char 		*quotePcrsString[],
				      const char 	*hostname,
				      const char 	*attestLogId,
				      MYSQL 		*mysql)
{
    uint32_t 	rc = 0;
    int		irc;
    uint32_t	pcrNum;				/* iterator */
    unsigned int storePcrWhiteList = FALSE;	/* flag to store first PCR values in
						   machines DB */
    unsigned int pcrinvalid = FALSE;		/* from first valid quote, only meaningful if
						   storePcrWhiteList is FALSE */
    MYSQL_RES 	*machineResult = NULL;
    char 	query[QUERY_LENGTH_MAX];
    const char *firstPcrsString[IMPLEMENTATION_PCR];

    /* get PCRs from the first attestation, this is the white list */
    if (rc == 0) {
	rc = SQ_GetFirstPcrs(firstPcrsString,
			     &machineResult,		/* freed @7 */
			     mysql,
			     hostname);
	/* no PCR white list */
	if (firstPcrsString[0] == NULL) {
	    /* store the first quote PCRs in the machines table as a white list */
	    storePcrWhiteList = TRUE;	/* flag, store it in machines DB */
	}
    }
    /* if there were first values, use as white list, check if any changed */
    if (!storePcrWhiteList) {
	if (rc == 0) {
	    if (vverbose) printf("processQuoteWhiteList: validate "
				 "quote BIOS PCRs vs. white list\n");  
	    for (pcrNum = 0 ; (pcrNum < 8) && !pcrinvalid ; pcrNum++) {
		irc = strcmp(firstPcrsString[pcrNum], quotePcrsString[pcrNum]);
		if (irc != 0) {
		    if (verbose) printf("INFO: processQuoteWhiteList: PCR %02u invalid\n", pcrNum);  
		    if (verbose) printf("INFO: processQuoteWhiteList: current PCR %s\n",
					quotePcrsString[pcrNum]);
		    if (verbose) printf("INFO: processQuoteWhiteList: valid   PCR %s\n",
					firstPcrsString[pcrNum]);
		    pcrinvalid = TRUE;	/* does not match PCR while list */
		    break;
		}
	    }
	    if (!pcrinvalid) {
		if (verbose) printf("INFO: processQuoteWhiteList: quote PCRs match white list\n");
	    }
	    else {
		if (verbose) printf("INFO: processQuoteWhiteList: "
				    "quote PCRs do not match white list\n");
	    }
	}
	/* PCRs invalid vs white list (only if there was a white list) */
	if (rc == 0) {
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "update attestlog set pcrinvalid = '%u' where id = '%s'",
			       pcrinvalid, attestLogId);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processQuoteWhiteList: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
    }
    else {	/* storePcrWhiteList */
	/* write PCRs to machines DB are the white list */
	uint32_t pcrNum;
	for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	    if (rc == 0) {
		int irc = snprintf(query, QUERY_LENGTH_MAX,
				   "update machines set pcr%02usha256 = '%s' where hostname = '%s'",
				   pcrNum, quotePcrsString[pcrNum], hostname);
		if (irc >= QUERY_LENGTH_MAX) {
		    printf("ERROR: processQuoteWhiteList: SQL query overflow\n");
		    rc = ASE_SQL_ERROR;
		}
	    }
	    if (rc == 0) {
		rc = SQ_Query(NULL, mysql, query);
	    }
	}
    }
    SQ_FreeResult(machineResult);	/* @9 */
    return rc;
}

/* processBiosEntries20Pass2() does the second pass through the client BIOS log entries.

 */

static uint32_t processBiosEntries20Pass2(const char *hostname,
					  const char *timestamp,
					  json_object *cmdJson,
					  MYSQL *mysql)
{
    uint32_t 		rc = 0;
    int 		eventNum;
    unsigned char 	*eventBin = NULL;
    /* common the TPM 1.2 and TPM 2.0 event */
    uint32_t		pcrIndex;
    uint8_t		*eventPtr = NULL;
    uint32_t 		eventSize = 0;
    const char		 *eventTypeString;
    char 		*pcrSha1Hexascii = NULL;
    char 		*pcrSha256Hexascii = NULL;

    for (eventNum = 0 ; (rc == 0) ; eventNum++) {
	/* get the next event */
	char *entryString = NULL;
	size_t eventLength;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&entryString,	/* freed @5 */
				 eventNum,
				 cmdJson);
	    /* Case 3: If there is no next event, done walking measurement list.  This is not a json
	       error, because the server does not know in advance how many entries the client will
	       send.  However, since BIOS PCRs did not match, there is an error to be processed
	       below.  */
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntries20Pass2: done, no event %u\n", eventNum);  
		break;			/* exit the BIOS event loop */
	    }
	}
	/* convert the event from a string to binary */
	if (rc == 0) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    entryString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries20Pass2: error scanning event %u\n", eventNum);
	    }
	}
	/* TPM 1.2 agile event log entry, first event */
	if (eventNum == 0) {
	    TCG_PCR_EVENT event;
	    /* unmarshal the event from binary to structure */
	    if (rc == 0) {
		if (vverbose) printf("processBiosEntries20Pass2: unmarshaling event %u\n", eventNum);
		unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
		uint32_t eventLengthPtr = eventLength;
		memset(event.event, 0, sizeof(event.event));	/* initialize to NUL terminated */
		rc = TSS_EVENT_Line_Unmarshal(&event, &eventBinPtr, &eventLengthPtr);
		if (rc != 0) {
		    printf("ERROR: processBiosEntries20Pass2: error unmarshaling event %u\n",
			   eventNum);
		}
	    }
	    if (rc == 0) {
		pcrIndex = event.pcrIndex;	/* for DB write */
		/* convert the event type to nul terminated ascii string */
		eventTypeString = TSS_EVENT_EventTypeToString(event.eventType);
		eventPtr = event.event;
		eventSize = event.eventDataSize;
		pcrSha256Hexascii = NULL;
		rc = Array_PrintMalloc(&pcrSha1Hexascii,		/* freed @3 */
				       event.digest,
				       SHA1_DIGEST_SIZE);
	    }
	}
	else {	/* TPM 2.0 events after event 0 */
	    TCG_PCR_EVENT2 event2;	/* TPM 2.0 hash agile event log entry */
	    /* unmarshal the event from binary to structure */
	    if (rc == 0) {
		if (vverbose) printf("processBiosEntries20Pass2: unmarshaling event %u\n",
				     eventNum);
		unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
		uint32_t eventLengthPtr = eventLength;
		memset(event2.event, 0, sizeof(event2.event));	/* initialize to NUL terminated */
		rc = TSS_EVENT2_Line_Unmarshal(&event2, &eventBinPtr, &eventLengthPtr);
		if (rc != 0) {
		    printf("ERROR: processBiosEntries20Pass2: error unmarshaling event %u\n",
			   eventNum);
		}
	    }
	    if (rc == 0) {
		pcrIndex = event2.pcrIndex;	/* for DB write */
		/* convert the event type to nul terminated ascii string */
		eventTypeString = TSS_EVENT_EventTypeToString(event2.eventType);
		eventSize = event2.eventSize;
		eventPtr = event2.event;
	    }
	    uint32_t count;
	    for (count = 0 ; (rc == 0)  && (count < event2.digests.count) && (count < 2) ; count++) {
		/* convert SHA1 PCR to hexascii */
		if (event2.digests.digests[count].hashAlg == ALG_SHA1_VALUE) {
		    rc = Array_PrintMalloc(&pcrSha1Hexascii,		/* freed @3 */
					   event2.digests.digests[count].digest.sha1,
					   SHA1_DIGEST_SIZE);
		}
		/* convert SHA256 PCR to hexascii */
		else if (event2.digests.digests[count].hashAlg == ALG_SHA256_VALUE) {
		    rc = Array_PrintMalloc(&pcrSha256Hexascii,		/* freed @4 */
					   event2.digests.digests[count].digest.sha256,
					   SHA256_DIGEST_SIZE);
		}
		else {
		    if (verbose) printf("processBiosEntries20Pass2: "
					"event %u unknown hash alg %04x\n",
					eventNum, event2.digests.digests[count].hashAlg);
		}
	    }
	}
	/* convert the event to nul terminated ascii string */
	char eventString[256];	/* matches schema */
	char *eventStringPtr = NULL;
	if (rc == 0) {
	    int length;
	    if (eventSize < sizeof(eventString)) {
		length = eventSize;
	    }
	    else {
		length = sizeof(eventString) -1;	/* truncate */
	    }
	    /* guess whether it's printable */
	    if (isprint(eventPtr[0]) && isprint(eventPtr[1])) {
		snprintf(eventString, sizeof(eventString), "%.*s", length, eventPtr);
		/* FIXME factor this for all sql inserts, escape single quotes */
		if (rc == 0) {
		    size_t len = strlen(eventString) +1; 
		    eventStringPtr = malloc(len);		/* freed @6 */
		    if (eventStringPtr == NULL) {
			printf("processBiosEntries20Pass2: Cannot alloc %lu for event\n", len);
			rc = TSS_RC_OUT_OF_MEMORY;
		    }
		    else {
			strcpy(eventStringPtr, eventString);
		    }
		}
		if (rc == 0) {
		    rc = SQ_EscapeQuotes(&eventStringPtr);
		}

	    }
	    /* some events are not printable as ascii */
	    else {
		Array_PrintMalloc(&eventStringPtr, eventPtr, length);
	    }
	    if (vverbose) printf("processBiosEntries20Pass2: event %u truncated: %s\n",
				 eventNum, eventStringPtr);
	}
	/* insert the event into the bioslog database */
	char query[QUERY_LENGTH_MAX];
	if (rc == 0) {
	    /* truncate the event going into the DB, mostly so that the sprintf does not overflow */
	    size_t length;
	    length = strlen(entryString);
	    if (length > ACS_JSON_EVENT_DBMAX) {
		entryString[ACS_JSON_EVENT_DBMAX] = '\0';
	    }
	    if (length > 511) {		/* FIXME coordinate with the DB schema */
		entryString[511] = '\0';
	    }
	    length = strlen(eventString);
	    if (length > ACS_JSON_EVENT_DBMAX) {
		eventString[ACS_JSON_EVENT_DBMAX] = '\0';
	    }
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
			       "insert into bioslog "
			       "(hostname, timestamp, entrynum, bios_entry, "
			       "pcrindex, pcrsha1, pcrsha256, "
			       "eventtype, event) "
			       "values ('%s','%s','%u','%s', "
			       "'%u','%s','%s', "
			       "'%s','%s')",
			       hostname, timestamp, eventNum, entryString,
			       pcrIndex, pcrSha1Hexascii, pcrSha256Hexascii,
			       eventTypeString, eventStringPtr);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processBiosEntries20Pass2: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
	/* loop free */
	free(eventBin);			/* @1 */
	free(pcrSha1Hexascii);		/* @3 */
	free(pcrSha256Hexascii);	/* @4 */
	free(entryString);		/* @5 */
	free(eventStringPtr);		/* @6 */
	eventBin = NULL;
	pcrSha1Hexascii = NULL;
	pcrSha256Hexascii = NULL;
	entryString = NULL;
	eventStringPtr = NULL;
    }	/* for eventNum */
    /* error case free */
    free(eventBin);		/* @1 */
    return rc;
}

#ifdef TPM_TPM12

/* processBiosEntries12Pass2() does the second pass through the client BIOS log entries.

 */

static uint32_t processBiosEntries12Pass2(const char *hostname,
					  const char *timestamp,
					  json_object *cmdJson,
					  MYSQL *mysql)
{
    uint32_t 		rc = 0;
    int 		eventNum;
    unsigned char 	*eventBin = NULL;

    for (eventNum = 0 ; (rc == 0) ; eventNum++) {
	/* get the next event */
	char *entryString = NULL;
	size_t eventLength;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&entryString,	/* freed @1 */
				 eventNum,
				 cmdJson);
	    /* Case 3: If there is no next event, done walking measurement list.  This is not a json
	       error, because the server does not know in advance how many entries the client will
	       send.  However, since BIOS PCRs did not match, there is an error to be processed
	       below.  */
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntries12Pass2: done, no event %u\n", eventNum);  
		break;			/* exit the BIOS event loop */
	    }
	}
	/* convert the event from a string to binary */
	if (rc == 0) {
	    rc = Array_Scan(&eventBin,		/* freed @2 */
			    &eventLength,
			    entryString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries12Pass2: error scanning event %u\n", eventNum);
	    }
	}
	TCG_PCR_EVENT event;	/* TPM 1.2 event log entry */
	/* unmarshal the event from binary to structure */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntries12Pass2: unmarshaling event %u\n", eventNum);
	    unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
	    uint32_t eventLengthPtr = eventLength;
	    rc = TSS_EVENT_Line_Unmarshal(&event, &eventBinPtr, &eventLengthPtr);
	    if (rc != 0) {
		printf("ERROR: processBiosEntries12Pass2: error unmarshaling event %u\n", eventNum);
	    }
	}
	/* convert the event type to nul terminated ascii string */
	const char *eventTypeString;
	if (rc == 0) {
	    eventTypeString = TSS_EVENT_EventTypeToString(event.eventType);
	    if (vverbose) printf("processBiosEntries12Pass2: event %u type %s\n",
				 eventNum, eventTypeString);
	}
	/* convert the event to nul terminated ascii string */
	char eventString[256];	/* matches schema */
	char *eventStringPtr;
	char *eventStringHexascii = NULL;
	if (rc == 0) {
	    if (isPrintableString(event.event)) {
		eventStringPtr = eventString;
		int length;
		if (event.eventDataSize < sizeof(eventString)) {
		    length = event.eventDataSize + 1;
		}
		else {
		    length = sizeof(eventString);	/* truncate */
		}
		snprintf(eventString, sizeof(eventString), "%.*s", length, event.event);
	    }
	    /* some events are not printable */
	    else {
		if (rc == 0) {
		    rc = Array_PrintMalloc(&eventStringHexascii,	/* freed @3 */
					   event.event,
					   event.eventDataSize);
		}
		if (rc == 0) {
		    eventStringPtr = eventStringHexascii; 
		}
	    }
	    if (vverbose) printf("processBiosEntries12Pass2: event %u event %s\n",
				 eventNum, eventStringPtr);
	}
	char *pcrSha1Hexascii = NULL;
	char *pcrSha256Hexascii = "";
	/* convert SHA1 PCR to hexascii */
	if (rc == 0) {
	    rc = Array_PrintMalloc(&pcrSha1Hexascii,		/* freed @4 */
				   event.digest,
				   SHA1_DIGEST_SIZE);
	}
	/* insert the event into the bioslog database */
	char query[QUERY_LENGTH_MAX];
	if (rc == 0) {
	    /* truncate the event going into the DB, mostly so that the sprintf does not overflow */
	    size_t length = strlen(entryString);
	    if (length > ACS_JSON_EVENT_DBMAX) {
		entryString[ACS_JSON_EVENT_DBMAX] = '\0';
	    }
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
		    "insert into bioslog "
		    "(hostname, timestamp, entrynum, bios_entry, "
		    "pcrindex, pcrsha1, pcrsha256, "
		    "eventtype, event) "
		    "values ('%s','%s','%u','%s', "
		    "'%u','%s','%s', "
		    "'%s','%s')",
		    hostname, timestamp, eventNum, entryString,
		    event.pcrIndex, pcrSha1Hexascii, pcrSha256Hexascii,
		    eventTypeString, eventStringPtr);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processBiosEntries12Pass2: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	}
	/* loop free */
	free(entryString);		/* @1 */
	free(eventBin);			/* @2 */
	free(eventStringHexascii);	/* @3 */
	free(pcrSha1Hexascii);		/* @4 */
	entryString = NULL;
	eventBin = NULL;
	eventStringHexascii = NULL;
	pcrSha1Hexascii = NULL;
    }	/* for eventNum */
    /* error case free */
    free(eventBin);		/* @1 */
    return rc;
}

#endif

/* processImaEntriesPass2() does the second pass through the client IMA log entries.

   For each entry, it does these checks:

   - If the digest is all zero, template_data is ignored, as it is intentionally invalid
   - Checks the digest against the template data
   - Unmarshals the template_data
   - Checks for the presence of a signature
   - Checks for a valid public key
   - Checks the signature
*/

static uint32_t processImaEntriesPass2(int *imasigver,
				       const char *hostname,	/* for DB row */
				       const char *boottime,	/* for DB row */
				       const char *timestamp,	/* for DB row */
				       json_object *cmdJson,	/* client command */
				       unsigned int firstEventNum, 	/* first IMA event to be
									   processed */
				       unsigned int lastEventNum,	/* last ima entry to be
									   processed */
				       const char *attestLogId,
				       MYSQL *mysql)		/* opened DB */
{
    uint32_t 	rc = 0;
    uint32_t	vrc = 0;	/* errors in verification */

    *imasigver = TRUE;
    
    unsigned char 	zeroDigest[TPM_SHA1_SIZE];	/* compare to SHA-1 digest in event log */
    if (rc == 0) {
	if (verbose) printf("INFO: processImaEntriesPass2: "
			    "Second pass, validating IMA entries %u to %u\n",
			    firstEventNum, lastEventNum);
    }
    if (rc == 0) {
	if (verbose) printf("INFO: processImaEntriesPass2: Second pass, template data\n");
	memset(zeroDigest, 0, TPM_SHA1_SIZE);
    }
    unsigned int eventNum;			/* the current IMA event number being processed */
    ImaEvent imaEvent;				/* the current IMA event being processed */
    IMA_Event_Init(&imaEvent);			/* so the first free works */
    unsigned char *eventBin = NULL;		/* so the first free works */
    unsigned char *eventFree = eventBin;	/* because IMA_Event_ReadBuffer moves the buffer */
    /* get endian'ness of client IMA event template data */
    int littleEndian = TRUE;
    if (rc == 0) { 
	rc = JS_Cmd_GetLittleEndian(&littleEndian,
				    cmdJson);
	rc = 0;	/* for backward compatibility, default to little endian if the client does not
		   report it */
    }    
    /* iterate through entries received from the client */
    for (eventNum = firstEventNum ; (rc == 0) && (firstEventNum <= lastEventNum) ; eventNum++) {

	/* get the next event */
	char *eventString = NULL;
	size_t eventBinLength;
	/* add a free at the beginning to handle the loop 'continue' case */
	IMA_Event_Free(&imaEvent);		/* @1 */
	free(eventFree);			/* @2 */
	eventFree = NULL;
	/* get the next IMA event from the client json */
	if (rc == 0) { 
	    vrc = JS_Cmd_GetImaEvent(&eventString,	/* freed @3 */
				     eventNum,
				     cmdJson);
	    /* if there is no next event, done walking measurement list */
	    if (vrc != 0) {	/* FIXME this should never happen */
		if (vverbose) printf("processImaEntriesPass2: done, no event %u\n", eventNum);  
		free(eventString);			/* @3 */
		eventString = NULL;
		break;
	    } 
	}
	/* errors cannot occur in the next few calls because they are the same as the first
	   pass */
	/* convert the event from a string to binary */
	if (rc == 0) {
	    Array_Scan(&eventBin,		/* eventFree freed @2 */
		       &eventBinLength,
		       eventString);
	}
	eventFree = eventBin;	/* for free(), because IMA_Event_ReadBuffer moves the buffer */
	/* unmarshal the event */
	if (rc == 0) {
	    if (vverbose) printf("processImaEntriesPass2: unmarshaling event %u\n", eventNum);
	    int endOfBuffer;	/* unused */
	    IMA_Event_ReadBuffer(&imaEvent,	/* freed @1 at end of loop, and beginning for
						   continue */
				 &eventBinLength,
				 &eventBin,
				 &endOfBuffer,
				 FALSE,	/* client sends to server in HBO */
				 TRUE);	/* get the template data for verification */
	}
	if (rc == 0) {
	    if (vverbose) printf("\n");		/* separate events */
	    if (vverbose) IMA_Event_Trace(&imaEvent, TRUE);
	}
	/* If the digest was all zero, the entry is invalid and template_data should be
	   ignored.  This is not an error. */
	int notAllZero;
	if (rc == 0) {
	    notAllZero = memcmp(imaEvent.digest, zeroDigest, TPM_SHA1_SIZE);
	    if (!notAllZero) {
		if (vverbose) printf("processImaEntriesPass2: skipping zero event %u\n", eventNum);
		free(eventString);			/* @3 */
		eventString = NULL;
		continue;
	    }
	}
	/* Check the IMA digest, the hash of the template data. If the verification fails, a
	   badevent row is inserted into the ima_log table. */
	char *filename = "";		/* for DB store if event is invalid */
	uint32_t badEvent = TRUE;
	uint32_t noSig = TRUE;
	uint32_t noKey = TRUE;
	uint32_t badSig = TRUE;
	if (rc == 0) {
	    rc = IMA_VerifyImaDigest(&badEvent,
				     &imaEvent,	/* the current IMA event being processed */
				     eventNum);	/* the current IMA event number */
	}
	/* unmarshal the template data */
	ImaTemplateData imaTemplateData;
	if ((rc == 0) && !badEvent) {
	    rc = verifyImaTemplateData(&badEvent,
				       &imaTemplateData,	/* unmarshaled template data */
				       littleEndian,
				       &imaEvent,	/* the current IMA event being processed */
				       eventNum); 	/* the current IMA event number */
	}
	/* if the event template hash validated and it unmarshaled, the file name is valid.  Save it
	   for the imalog DB row. */
	if ((rc == 0) && !badEvent) {
	    filename = (char *)imaTemplateData.imaTemplateNNG.fileName;
	}
	/* verify that a signature is present */
	if ((rc == 0) && !badEvent) {
	    rc = verifyImaSigPresent(&noSig,
				     &imaTemplateData,	/* unmarshaled template data */
				     eventNum);		/* the current IMA event number */
	}
	unsigned int imaKeyNumber;
	/* get the IMA public key index corresponding to the IMA event fingerprint */
	if ((rc == 0) && !badEvent && !noSig) {
	    rc = getImaPublicKeyIndex(&noKey,		/* TRUE if not found */
				      &imaKeyNumber,	/* index */
				      &imaTemplateData,
				      eventNum);
	}
	/* verify the signature */
	if ((rc == 0) && !badEvent && !noSig && !noKey) {
	    rc = verifyImaSignature(&badSig,		/* verification return code */
				    &imaTemplateData,	/* unmarshaled template data */
				    imaRsaPkey[imaKeyNumber],	/* EVP_PKEY public key token */
				    eventNum);	/* the current IMA event number */
	}
	if (badEvent || noSig || noKey || badSig) {
	    *imasigver = FALSE;
	}
	/* insert the event into the imalog database */
	char query[QUERY_LENGTH_MAX];
	/* This hack escapes the ' character in a file name. */
	/* FIXME this should be factored for all client data written to the DB */
	char *filenameEscaped = NULL;
	if (rc == 0) {
	    size_t len = strlen(filename) +1; 
	    filenameEscaped = malloc(len);		/* freed @4 */
	    if (filenameEscaped == NULL) {
		printf("processImaEntriesPass2: Cannot alloc %lu for filename\n", len);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	    else {
		strcpy(filenameEscaped, filename);
	    }
	}
	if (rc == 0) {
	    rc = SQ_EscapeQuotes(&filenameEscaped);
	}
	if (rc == 0) {
	    /* truncate the event going into the DB, mostly so that the sprintf does not overflow */
	    size_t length = strlen(eventString);
	    if (length > ACS_JSON_EVENT_DBMAX) {
		eventString[ACS_JSON_EVENT_DBMAX] = '\0';
	    }
	    int irc = snprintf(query, QUERY_LENGTH_MAX,
		    "insert into imalog "
		    "(hostname, boottime, timestamp, entrynum, ima_entry, "
		    "filename, badevent, nosig, nokey, badsig) "
		    "values ('%s','%s','%s','%u','%s', "
		    "'%s','%u','%u','%u','%u')",
		    hostname, boottime, timestamp, eventNum, eventString,
		    filenameEscaped, badEvent, noSig, noKey, badSig);
	    if (irc >= QUERY_LENGTH_MAX) {
		printf("ERROR: processImaEntriesPass2: SQL query overflow\n");
		rc = ASE_SQL_ERROR;
	    }
	}
	if (rc == 0) {
	    rc = SQ_Query(NULL, mysql, query);
	    
	}
	IMA_Event_Free(&imaEvent);		/* @1 */
	free(eventFree);			/* @2 */
	free(eventString);			/* @3 */
	free(filenameEscaped);			/* @4 */
	eventFree = NULL;
	eventString = NULL;
	filenameEscaped = NULL;
    }		/* for each event */
    char query[QUERY_LENGTH_MAX];
    if (rc == 0) {
	int irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update attestlog set "
			   "imasigver = '%u' where id = '%s'",
			   *imasigver, attestLogId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processImaEntry: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }	
    return rc;
}


/* processEnrollRequest() handles the first client to server message for a client attestation key
   enrollment.
   
   The client command is of the form:
   
   {
   "command":"enrollrequest",
   "hostname":"cainl.watson.ibm.com",
   "tpmvendor":"IBM ",
   "ekcert":"hexascii",
   "akpub":"hexascii"
   }

   The response to the client is of the form:

   "response":"enrollrequest",
   "credentialblob":"hexascii",
   "secret":"hexascii"
   }   

*/

static uint32_t processEnrollRequest(unsigned char **rspBuffer,
				     uint32_t *rspLength,
				     json_object *cmdJson,
				     const char *listFilename)
{
    uint32_t  		rc = 0;
    MYSQL_RES 		*machineResult = NULL;
    char 		*machineId = NULL;	/* row being updated */

    if (vverbose) printf("INFO: processEnrollRequest: Entry\n");

    /* get the client machine name from the command */
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *tpmVendorString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&tpmVendorString , "tpmvendor", ACS_JSON_TPM_MAX, cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *ekCertString = NULL;	/* hexascii */
    if (rc == 0) {
	rc = JS_ObjectGetString(&ekCertString, "ekcert", ACS_JSON_PEMCERT_MAX, cmdJson);
    }
    /* get the client attestation key TPMT_PUBLIC from the command */
    const char *attestPubString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&attestPubString, "akpub", ACS_JSON_PUB_MAX, cmdJson);
    }
    /*
      if the machine is already enrolled, error
    */
    /* connect to the db */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @2 */	
    }
    /* get the DB information for this machine */
    if (rc == 0) {
	const char 		*akCertificatePem = NULL;
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @3 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				NULL,			/* boottime */
				NULL,			/* imaevents */
				NULL,			/* imapcr */
				&machineResult,		/* freed @4 */
				mysql,
				hostname);
	if (rc !=0) {
	    printf("processEnrollRequest: New host is not in DB (error is expected)\n");
	    rc = 0;	/* host is not in DB, error is expected */
	}
	/* client hostname is already in DB.  The client sent another enrollment request. */
	else {
	    if (akCertificatePem != NULL) {
		printf("ERROR: processEnrollRequest: "
		       "row for hostname %s already exists in machine table\n",
		       hostname);  
		rc = ACE_ENROLLED;
	    }
	    /* client hostname is already in DB, but enrollment is not valid.  If the client for
	       some reason aborted the protocol, remove the DB entry and proceed. */
	    else {
		printf("ERROR: processEnrollRequest: "
		       "row for hostname %s is invalid in machine table\n",
		       hostname);  
		rc = SQ_RemoveMachineEntry(mysql, hostname);
	    }
	}
    }    
    /* validate that the EK certificate came from an authentic TPM */
    TPMT_PUBLIC ekPub;	/* public part of client EK */
    X509 *ekX509Certificate = NULL;
    if (rc == 0) {
	rc = validateEkCertificate(&ekPub,		/* output, TPMT_PUBLIC */
				   &ekX509Certificate,	/* output, X509, freed @5 */
				   ekCertString,	/* hexascii */
				   listFilename);
    }
    /* convert EK certificate X509 to PEM */
    char *ekCertificatePemString = NULL;
    if (rc == 0) {
	rc = convertX509ToPemMem(&ekCertificatePemString,	/* freed @6 */
				 ekX509Certificate);
    }
    if (rc == 0) {
	if (vverbose) printf("processEnrollRequest: EK certificate PEM format\n%s\n",
			     ekCertificatePemString);
    }
    /* convert EK certificate to string */
    char *ekCertificateX509String = NULL;
    if (rc == 0) {
	rc = convertX509ToString(&ekCertificateX509String,	/* freed @7 */
				 ekX509Certificate);
    }
    /* escape single quotes for SQL statement */
    if (rc == 0) {
	rc = SQ_EscapeQuotes(&ekCertificateX509String);
    }
    /* validate the attestation key properties, but don't trust them yet */
    TPMT_PUBLIC attestPub;	/* unmarshaled structure */
    if (rc == 0) {
	rc = validateAttestationKey(&attestPub,		/* returns unmarshaled structure */
				    attestPubString);
    }
    TPM2B_DIGEST challenge;		/* symmetric key, use AES 256 */
    char *challengeString = NULL;
    if (rc == 0) {
	rc = generateEnrollmentChallenge(&challenge,
					 &challengeString);	/* freed @8 */
    }
    char *credentialBlobString = NULL;
    TPM2B_ID_OBJECT credentialBlob;
    char *secretString = NULL;
    TPM2B_ENCRYPTED_SECRET secret;
    /* run makecredential, wrap the symmetric key with the client EK public key, etc. */
    if (rc == 0) {
	rc = generateCredentialBlob(&credentialBlobString,	/* freed @9 */
				    &credentialBlob,
				    &secretString,		/* freed @10 */
				    &secret,
				    &attestPub,		/* attestation public key, for name */
				    &ekPub,		/* to wrap credential */
				    &challenge);	/* server to client challenge */
    }
    /* save the challenge in the DB */
    char query[QUERY_LENGTH_MAX];
    /* create a new client hostname DB entry, mark not valid (until client activates credential) */
    if (rc == 0) {
	int irc = snprintf(query, QUERY_LENGTH_MAX,
			   "insert into machines "
			   "(hostname, tpmvendor, ekcertificatepem, ekcertificatetext, "
			   "challenge, attestpub) "
			   "values ('%s','%s %s','%s','%s','%s','%s')",
			   hostname, tpmVendorString, "TPM 2.0",
			   ekCertificatePemString, ekCertificateX509String,
			   challengeString, attestPubString);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processEnrollRequest: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    /* create the enrollcert return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @1 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response",
				   json_object_new_string("enrollrequest"));
	    json_object_object_add(response, "credentialblob",
				   json_object_new_string(credentialBlobString));
	    json_object_object_add(response, "secret",
				   json_object_new_string(secretString));
	}
	/* processing error */
	else {
	    rc1 = JS_Rsp_AddError(response, rc);
	}
	if (rc1 == 0) {	
	    rc = JS_ObjectSerialize(rspLength,
				    (char **)rspBuffer,	/* freed by caller */
				    response);		/* @1 */
	}
    }
    /* could not construct response */
    else {
	rc = rc1;
    }
    SQ_Close(mysql);			/* @2 */
    free(machineId);			/* @3 */
    SQ_FreeResult(machineResult);	/* @4 */
    if (ekX509Certificate != NULL) {
	X509_free(ekX509Certificate);   /* @5 */
    }
    free(ekCertificatePemString);	/* @6 */
    free(ekCertificateX509String);	/* @7 */
    free(challengeString);		/* @8 */
    free(credentialBlobString);		/* @9 */
    free(secretString);			/* @10 */
    return rc;
}

#ifdef TPM_TPM12

/* processEnrollRequest12() handles the first client to server message for a client attestation key
   enrollment.
   
   The client command is of the form:
   
   {
   "command":"enrollrequest12",
   "hostname":"cainl.watson.ibm.com",
   "tpmvendor":"IBM ",
   "ekcert":"hexascii",
   "akpub":"hexascii"
   }

   The response to the client is of the form:

   "response":"enrollrequest12",
   "credentialblob":"hexascii",
   }   
*/

static uint32_t processEnrollRequest12(unsigned char **rspBuffer,
				       uint32_t *rspLength,
				       json_object *cmdJson,
				       const char *listFilename)
{
    uint32_t  		rc = 0;
    MYSQL_RES 		*machineResult = NULL;
    char 		*machineId = NULL;	/* row being updated */

    if (vverbose) printf("INFO: processEnrollRequest12: Entry\n");

    /* get the client machine name from the command */
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *tpmVendorString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&tpmVendorString , "tpmvendor", ACS_JSON_TPM_MAX, cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *ekCertString = NULL;	/* hexascii */
    if (rc == 0) {
	rc = JS_ObjectGetString(&ekCertString, "ekcert", ACS_JSON_PEMCERT_MAX, cmdJson);
    }
    /* get the client attestation key TPM_PUBKEY from the command */
    const char *attestPubString12 = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&attestPubString12, "akpub",  ACS_JSON_PUB_MAX, cmdJson);
    }
    /*
      if the machine is already enrolled, error
    */
    /* connect to the db */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @2 */	
    }
    /* get the DB information for this machine */
    if (rc == 0) {
	const char 		*akCertificatePem = NULL;
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @3 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				NULL,			/* boottime */
				NULL,			/* imaevents */
				NULL,			/* imapcr */
				&machineResult,		/* freed @4 */
				mysql,
				hostname);
	if (rc !=0) {
	    printf("processEnrollRequest12: New host is not in DB (error is expected)\n");
	    rc = 0;	/* host is not in DB, error is expected */
	}
	/* client hostname is already in DB.  The client sent another enrollment request. */
	else {
	    if (akCertificatePem != NULL) {
		printf("ERROR: processEnrollRequest12: "
		       "row for hostname %s already exists in machine table\n",
		       hostname);  
		rc = ACE_ENROLLED;
	    }
	    /* client hostname is already in DB, but enrollment is not valid.  If the client for
	       some reason aborted the protocol, remove the DB entry and proceed. */
	    else {
		printf("ERROR: processEnrollRequest12: "
		       "row for hostname %s is invalid in machine table\n",
		       hostname);  
		rc = SQ_RemoveMachineEntry(mysql, hostname);
	    }
	}
    }    
    /* validate that the EK certificate came from an authentic TPM */
    TPMT_PUBLIC ekPub;	/* public part of client EK */
    X509 *ekX509Certificate = NULL;
    if (rc == 0) {
	rc = validateEkCertificate(&ekPub,		/* output, TPMT_PUBLIC */
				   &ekX509Certificate,	/* output, X509, freed @5 */
				   ekCertString,	/* hexascii */
				   listFilename);
    }
    /* convert EK certificate X509 to PEM */
    char *ekCertificatePemString = NULL;
    if (rc == 0) {
	rc = convertX509ToPemMem(&ekCertificatePemString,	/* freed @6 */
				 ekX509Certificate);
    }
    if (rc == 0) {
	if (vverbose) printf("processEnrollRequest12: EK certificate PEM format\n%s\n",
			     ekCertificatePemString);
    }
    /* convert EK certificate to string */
    char *ekCertificateX509String = NULL;
    if (rc == 0) {
	rc = convertX509ToString(&ekCertificateX509String,	/* freed @7 */
				 ekX509Certificate);
    }     
    /* escape single quotes for SQL statement */
    if (rc == 0) {
	rc = SQ_EscapeQuotes(&ekCertificateX509String);
    }
    /* validate the attestation key properties, but don't trust them yet */
    TPM_PUBKEY attestPub12;	/* unmarshaled structure */
    TPMT_PUBLIC attestPub20;
    if (rc == 0) {
	rc = validateAttestationKey12(&attestPub20,	/* returns unmarshaled structures */	
				      &attestPub12,
				      attestPubString12);
    }
    /* convert the TPMT_PUBLIC TPM 2.0 format attestPub to a string for storage in the database */
    char 	*attestPubString20 = NULL;
    if (rc == 0) {
	rc = Structure_Print(&attestPubString20, 		/* freed @10 */
			     &attestPub20,
			     (MarshalFunction_t)TSS_TPMT_PUBLIC_Marshalu);
    }
    TPM2B_DIGEST challenge;		/* symmetric key, use AES 256 */
    char *challengeString = NULL;
    if (rc == 0) {
	rc = generateEnrollmentChallenge(&challenge,
					 &challengeString);	/* freed @8 */
    }
    uint8_t 			encBlob[2048/8];	/* encrypted TPM_EK_BLOB */
    char 			*credentialBlobString = NULL;

    /* run makecredential, wrap the symmetric key with the client EK public key, etc. */
    if (rc == 0) {
	rc = generateCredentialBlob12(encBlob,			/* for debug */
				      sizeof(encBlob),
				      &credentialBlobString,	/* freed @9 */
				      &attestPub12,	/* TPM_PUBKEY attestation public key */
				      &ekPub,		/* TPMT_PUBLIC EK public key */
				      &challenge);	/* server to client challenge */

    }
    /* save the challenge in the DB */
    char query[QUERY_LENGTH_MAX];
    /* create a new client hostname DB entry, mark not valid (until client activates credential) */
    if (rc == 0) {
	int irc = snprintf(query, QUERY_LENGTH_MAX,
			   "insert into machines "
			   "(hostname, tpmvendor, ekcertificatepem, ekcertificatetext, "
			   "challenge, attestpub) "
			   "values ('%s','%s %s','%s','%s','%s','%s')",
			   hostname, tpmVendorString, "TPM 1.2",
			   ekCertificatePemString, ekCertificateX509String,
			   challengeString, attestPubString20);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processEnrollRequest12: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    /* create the enrollcert return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @1 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response",
				   json_object_new_string("enrollrequest12"));
	    json_object_object_add(response, "credentialblob",
				   json_object_new_string(credentialBlobString));
	}
	/* processing error */
	else {
	    rc1 = JS_Rsp_AddError(response, rc);
	}
	if (rc1 == 0) {	
	    rc = JS_ObjectSerialize(rspLength,
				    (char **)rspBuffer,	/* freed by caller */
				    response);		/* @1 */
	}
    }
    /* could not construct response */
    else {
	rc = rc1;
    }
    SQ_Close(mysql);			/* @2 */
    free(machineId);			/* @3 */
    SQ_FreeResult(machineResult);	/* @4 */
    if (ekX509Certificate != NULL) {
	X509_free(ekX509Certificate);   /* @5 */
    }
    free(ekCertificatePemString);	/* @6 */
    free(ekCertificateX509String);	/* @7 */
    free(challengeString);		/* @8 */
    free(credentialBlobString);		/* @9 */
    free(attestPubString20);		/* @10 */
    return rc;
}

#endif

/* processEnrollCert() handles the second client to server message for a client attestation key
   enrollment.

   The client command is of the form:
   
   {
   "command":"enrollcert",
   "hostname":"cainl.watson.ibm.com",
   "challenge":hexascii""
   }

   The response to the client is of the form:

   {
   "response":"enrollcert"
   "akcert":"hexascii"
   }
*/

static uint32_t processEnrollCert(unsigned char **rspBuffer,
				  uint32_t *rspLength,
				  json_object *cmdJson)
{
    uint32_t  	rc = 0;		/* server error, should never occur, aborts processing */
    int		irc;
    
    MYSQL_RES 		*machineResult = NULL;
    char 		*machineId = NULL;	/* row being updated */

    if (vverbose) printf("INFO: processEnrollCert: Entry\n");
    /* get the client machine name from the command */
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", ACS_JSON_HOSTNAME_MAX, cmdJson);
    }
    /* get the decrypted challenge from the command */
    const char *challengeString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&challengeString, "challenge", ACS_JSON_HASH_MAX, cmdJson);
    }
    /*
      if the machine is already enrolled, error
    */
    /* connect to the db */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @1 */	
    }
    /* get the DB information for this client machine.  If the client machine hostname is not in the
       DB, or if the enrollment is already valid, error. */
    const char *ekCertificatePem = NULL;
    const char *akCertificatePem = NULL;
    const char *expectChallengeString;
    const char *attestPubString = NULL;
    if (rc == 0) {
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @2 */
				NULL,			/* tpmvendor */
				&expectChallengeString, /* challenge */
				&attestPubString,	/* attestpub */
				&ekCertificatePem,	/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				NULL,			/* boottime */
				NULL,			/* imaevents */
				NULL,			/* imapcr */
				&machineResult,		/* freed @3 */
				mysql,
				hostname);
	/* client machine hostname not in DB.  This indicates that the client sent commands out of
	   order. */
	if (rc != 0) {
	    printf("ERROR: "
		   "processEnrollCert: hostname %s missing enrollment request\n",
		   hostname);  
	    rc = ACE_NO_ENROLL_REQ;
	}
	/* client machine hostname already enrolled. This indicates that the client sent an
	   extraneous enrollment command.  */
	else if (akCertificatePem != NULL) {
	    printf("ERROR: "
		   "processEnrollCert: hostname %s already enrolled\n",
		   hostname);  
	    rc = ACE_ENROLLED;
	}
    }
    /* verify that the client decrypted the challenge correctly */
    if (rc == 0) {
	irc = strcmp(expectChallengeString, challengeString);
	if (irc == 0) {
	    if (verbose) printf("INFO: processEnrollCert: Client and server challenges match\n");
	}
	else {
	    printf("ERROR: processEnrollCert: Client and server challenge mismatch\n");
	    rc = ACE_MISMATCH_CERT;
	}
    }
    TPMT_PUBLIC attestPub;		/* unmarshaled structure */
    uint8_t *attestPubBin = NULL;
    size_t attestPubBinLen;
    /* convert the client attestation key string to binary */
    if (rc == 0) {
	rc = Array_Scan(&attestPubBin,		/* output binary, freed @4 */
			&attestPubBinLen,
			attestPubString);	/* input string */
    }
    /* unmarshal the binary to a TPMT_PUBLIC attestation key */
    uint8_t *tmpptr = attestPubBin;	/* unmarshal moves the pointer */
    uint32_t tmpLengthPtr = attestPubBinLen;
    if (rc == 0) {
	rc = TSS_TPMT_PUBLIC_Unmarshalu(&attestPub, &tmpptr, &tmpLengthPtr, TRUE);
    }
    /* generate the attestation key certificate.  Sign with the server privacy CA. */
    char *akX509CertString = NULL;	/* attestation key certificate in openssl printed format */
    char *akCertPemString = NULL;	/* attestation key certificate in PEM */
    uint8_t *attestCertBin = NULL;	/* attestation key certificate in DER */
    uint32_t attestCertBinLen;
    if (rc == 0) {
	rc = generateAttestationCert(&akX509CertString,	/* freed @5 */
				     &akCertPemString,	/* freed @6 */
				     &attestCertBin,	/* freed @7 */
				     &attestCertBinLen,
				     hostname,
				     &attestPub);
    }
    if (rc == 0) {
	if (vverbose) printf("processEnrollCert: server PEM attestation certificate\n%s\n",
			     akCertPemString);
	if (verbose) printf("INFO: processEnrollCert: server X509 attestation certificate\n%s\n",
			    akX509CertString);
	if (vverbose) TSS_PrintAll("processEnrollCert: attestation certificate:",
				   attestCertBin, attestCertBinLen);
    }
    /* if the certificate matches, update client machine DB entry with AK certificate */
    char query[QUERY_LENGTH_MAX];
    if (rc == 0) {
	int irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update machines set akcertificatepem = '%s', akcertificatetext = '%s', "
			   "imaevents = '%u' where id = '%s'",
			   akCertPemString, akX509CertString , 0, machineId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processEnrollCert: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
    /* construct a enrollment timestamp and add to machine DB */
    char enrolledTime[80];
    if (rc == 0) {
	getTimeStamp(enrolledTime, sizeof(enrolledTime));
    }
    if (rc == 0) {
	int irc = snprintf(query, QUERY_LENGTH_MAX,
			   "update machines set enrolled = '%s' where id = '%s'",
			   enrolledTime, machineId);
	if (irc >= QUERY_LENGTH_MAX) {
	    printf("ERROR: processEnrollCert: SQL query overflow\n");
	    rc = ASE_SQL_ERROR;
	}
    }
    if (rc == 0) {
	rc = SQ_Query(NULL, mysql, query);
    }
#ifdef ACS_BLOCKCHAIN
    /* Send the results to blockchain log */
    if (rc == 0) {
	rc  = BC_Enroll(ekCertificatePem, akCertPemString);
    }
#endif
    /* create the enrollcert return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);	/* freed @1 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("enrollcert"));
	}
	if (rc == 0) {
	    json_object_object_add(response, "akcert", json_object_new_string(akCertPemString));
	}
	/* processing error */
	else {
	    rc1 = JS_Rsp_AddError(response, rc);
	}
	if (rc1 == 0) {	
	    rc = JS_ObjectSerialize(rspLength,
				    (char **)rspBuffer,	/* freed by caller */
				    response);		/* @1 */
 	}
    }
    /* could not construct response */
    else {
	rc = rc1;
    }
    SQ_Close(mysql);			/* @1 */
    free(machineId);			/* @2 */
    SQ_FreeResult(machineResult);	/* @3 */
    free(attestPubBin);			/* @4 */
    free(akX509CertString);		/* @5 */
    free(akCertPemString);		/* @6 */
    free(attestCertBin);		/* @7 */
    return rc;
}

/* validateEkCertificate() validates the EK certificate against the TPM vendor root.

   It returns the EK public key as a TPMT_PUBLIC, for use in makecredential

   'listFilename' is a file of file names of TPM vendor root certificates that the server trusts.
*/

static uint32_t validateEkCertificate(TPMT_PUBLIC *ekPub,	/* output */
				      X509 **ekX509Certificate,	/* output, freed by caller */
				      const char *ekCertString,	/* hexascii */
				      const char *listFilename)
{
    uint32_t 		rc = 0;
    unsigned int	i;

    if (vverbose) printf("validateEkCertificate: Entry\n");
    /*
      convert the EK certificate string to an X509 structure
    */
    if (vverbose) printf("validateEkCertificate: Convert EK certificate string to X509 structure\n");
    uint8_t *ekCertBin = NULL;
    size_t ekCertBinLen;
    /* convert EK certificate string to binary */
    if (rc == 0) {
	rc = Array_Scan(&ekCertBin,	/* output binary, freed @4 */
			&ekCertBinLen,
			ekCertString);	/* input string */
    }
    /* unmarshal the EK certificate DER stream to EK certificate X509 structure */
    if (rc == 0) {
	unsigned char *tmpCert = ekCertBin;		/* temp because d2i moves the pointer */
	*ekX509Certificate = d2i_X509(NULL,		/* freed by caller */
				      (const unsigned char **)&tmpCert, ekCertBinLen);
	if (*ekX509Certificate == NULL) {
	    printf("ERROR: validateEkCertificate: Could not parse X509 EK certificate\n");
	    rc = ACE_INVALID_CERT;
	}
    }
    if (rc == 0) {
	if (vverbose) {
	    int		irc;
	    irc = X509_print_fp(stdout, *ekX509Certificate);
	    if (irc != 1) {
		printf("ERROR: convertPemToX509: Error in certificate print X509_print_fp()\n");
		rc = ACE_INVALID_CERT;
	    }
	}
	printf("validateEkCertificate: "
	       "Build the EK certificate root certificate store\n");
    }
    /* get the TPM vendor root certificates */
    char		*rootFilename[MAX_ROOTS];
    unsigned int	rootFileCount = 0;
    for (i = 0 ; i < MAX_ROOTS ; i++) {
	rootFilename[i] = NULL;    				/* for free @1 */
    }
    /* get a list of TPM vendor EK root certificates */
    if (rc == 0) {
	rc = getRootCertificateFilenames(rootFilename,		/* freed @1 */
					 &rootFileCount,
					 listFilename,
					 vverbose);
    }
    if (rc == 0) {
	if (vverbose)
	    printf("validateEkCertificate: Validate the client EK certificate against the root\n");
    }
    /* validate the EK certificate against the root */
    if (rc == 0) {
	rc = verifyCertificate(*ekX509Certificate,
			       (const char **)rootFilename,
			       rootFileCount,
			       vverbose);
    }
    /*
      construct the TPMT_PUBLIC for the EK public key
    */
    /* determine if the EK certificate is RSA or EC */
    int 		pkeyType;
    TPMI_RH_NV_INDEX	ekCertIndex;
    if (rc == 0) {
	EVP_PKEY 		*pkey = NULL;
	pkey = X509_get_pubkey(*ekX509Certificate);		/* freed @2 */
	if (pkey != NULL) {
	    pkeyType = getRsaPubkeyAlgorithm(pkey);
	    if (pkeyType == EVP_PKEY_RSA) {
		ekCertIndex = EK_CERT_RSA_INDEX;
	    }
	    else if (pkeyType ==  EVP_PKEY_EC) {
		ekCertIndex = EK_CERT_EC_INDEX;
	    }
	    else {
		printf("ERROR: validateEkCertificate: Public key is not RSA or EC\n");
		rc = ACE_INVALID_CERT;
	    }
	    /* for TPM 2.0, standard X509, validate the certificate key usage */
	    if (rc == 0) {
		rc = verifyKeyUsage(*ekX509Certificate, pkeyType, vverbose);
	    }
	}
	/* TPM 1.2 EK certificates have a non-standard OID, so X509_get_pubkey() fails.  However,
	   TPM 1.2 is always RSA. */
	else {
	    pkeyType = EVP_PKEY_RSA;
	    ekCertIndex = EK_CERT_RSA_INDEX;
	}
	EVP_PKEY_free(pkey);   		/* @2 */
    }
    uint8_t *modulusBin = NULL;	
    int modulusBytes;
    /* start with the default IWG template.  This may not be the actual client TPM EK template,
       but it's good enough to load the EK public part.  The server cannot, of course, use the
       template to create the client EK. */
    if (rc == 0) {
	rc = convertCertificatePubKey(&modulusBin,	/* freed @3 */
				      &modulusBytes,
				      *ekX509Certificate,
				      ekCertIndex,
				      vverbose);
    }
    if (rc == 0) {
	if (pkeyType == EVP_PKEY_RSA) {
	    getRsaTemplate(ekPub);
	    /* FIXME sanity check modulusBytes */
	    ekPub->unique.rsa.t.size = modulusBytes;
	    memcpy(&ekPub->unique.rsa.t.buffer, modulusBin, modulusBytes);
	}
	else {
	    getEccTemplate(ekPub);
	    /* FIXME sanity check modulusBytes */
	    ekPub->unique.ecc.x.t.size = 32;	
	    memcpy(&ekPub->unique.ecc.x.t.buffer, modulusBin +1, 32);	
	    ekPub->unique.ecc.y.t.size = 32;	
	    memcpy(&ekPub->unique.ecc.y.t.buffer, modulusBin +33, 32);	
	    
	}
    }
    for (i = 0 ; i < rootFileCount ; i++) {
	free(rootFilename[i]);	   	/* @1 */
    }
    free(modulusBin);			/* @3 */
    free(ekCertBin);			/* @4 */
    return rc;
}

/* validateAttestationKey() validates the attestation key properties.  The values are not trusted
   yet, since the client is just sending a public key.

   Returns unmarshaled attestPub.
*/

static uint32_t validateAttestationKey(TPMT_PUBLIC *attestPub,
				       const char *attestPubString)
{
    uint32_t rc = 0;

    if (vverbose) printf("validateAttestationKey: "
			 "Convert attestation key string to TPMT_PUBLIC structure\n");
    uint8_t *attestPubBin = NULL;
    size_t attestPubBinLen;
    /* convert the client attestation key string to binary */
    if (rc == 0) {
	rc = Array_Scan(&attestPubBin,		/* output binary, freed @1 */
			&attestPubBinLen,
			attestPubString);	/* input string */
    }
    /* unmarshal the binary to a TPMT_PUBLIC attestation key */
    uint8_t *tmpptr = attestPubBin;	/* unmarshal moves the pointer */
    uint32_t tmpLengthPtr = attestPubBinLen;
    if (rc == 0) {
	rc = TSS_TPMT_PUBLIC_Unmarshalu(attestPub, &tmpptr, &tmpLengthPtr, TRUE);
    }
    /* validate the attestation public key attributes */
    if (rc == 0) {
	/* b TRUE is an error */
	int b1 = ((attestPub->type != TPM_ALG_RSA) && (attestPub->type != TPM_ALG_ECC));
	int b2 = (attestPub->nameAlg != TPM_ALG_SHA256);
	int b3 = ((attestPub->objectAttributes.val & TPMA_OBJECT_FIXEDTPM) == 0);
	int b4 = ((attestPub->objectAttributes.val & TPMA_OBJECT_FIXEDPARENT) == 0);
	int b5 = ((attestPub->objectAttributes.val & TPMA_OBJECT_SENSITIVEDATAORIGIN) == 0);
	int b6 = ((attestPub->objectAttributes.val & TPMA_OBJECT_SIGN) == 0);
	int b7 = ((attestPub->objectAttributes.val & TPMA_OBJECT_RESTRICTED) == 0);
	int b8 = ((attestPub->objectAttributes.val & TPMA_OBJECT_DECRYPT) != 0);
	int b9;
	int b10;
	int b11;
	int b12;
	if (attestPub->type == TPM_ALG_RSA) {
	    b9 = (attestPub->parameters.rsaDetail.scheme.scheme != TPM_ALG_RSASSA);
	    b10 = (attestPub->parameters.rsaDetail.scheme.details.rsassa.hashAlg != TPM_ALG_SHA256);
	    b11 = (attestPub->parameters.rsaDetail.keyBits != 2048);
	    b12 = (attestPub->parameters.rsaDetail.exponent != 0);
	}
	if (attestPub->type == TPM_ALG_ECC) {
	    b9 = attestPub->parameters.eccDetail.scheme.details.ecdsa.hashAlg != TPM_ALG_SHA256;
	    b10 = attestPub->parameters.eccDetail.scheme.scheme != TPM_ALG_ECDSA;
	    b11 = attestPub->parameters.eccDetail.curveID != TPM_ECC_NIST_P256;
	    b12 = attestPub->parameters.eccDetail.kdf.scheme != TPM_ALG_NULL;
	}
	if (b1 || b2 || b3 || b4 || b5 || b6 || b7 || b8 || b9 || b10 || b11 || b12) {
	    printf("ERROR: validateAttestationKey: Invalid attest public key parameter\n");  
	    rc = ACE_INVALID_KEY;
	}
    }
    if (rc == 0) {
	if (verbose) printf("INFO: validateAttestationKey: Attestation key parameters are valid\n");
    }
    free(attestPubBin);		/* @1 */
    return rc;
}

#ifdef TPM_TPM12

/* validateAttestationKey12() validates the attestation key properties.  The values are not trusted
   yet, since the client is just sending a public key.

   Returns unmarshaled attestPub.
*/

static uint32_t validateAttestationKey12(TPMT_PUBLIC *attestPub20,
					 TPM_PUBKEY *attestPub12,
					 const char *attestPubString)
{
    uint32_t rc = 0;

    if (vverbose) printf("validateAttestationKey12: "
			 "Convert attestation key string to TPM_PUBKEY structure\n");
    uint8_t *attestPubBin = NULL;
    size_t attestPubBinLen;
    /* convert the client attestation key string to binary */
    if (rc == 0) {
	rc = Array_Scan(&attestPubBin,		/* output binary, freed @1 */
			&attestPubBinLen,
			attestPubString);	/* input string */
    }
    /* unmarshal the binary to a TPMT_PUBLIC attestation key */
    uint8_t *tmpptr = attestPubBin;	/* unmarshal moves the pointer */
    uint32_t tmpLengthPtr = attestPubBinLen;
    if (rc == 0) {
	rc = TSS_TPM_PUBKEY_Unmarshalu(attestPub12, &tmpptr, &tmpLengthPtr);
    }
    /* validate the attestation public key attributes */
    if (rc == 0) {
	/* b TRUE is an error */
	int b1 = (attestPub12->algorithmParms.algorithmID != TPM_ALG_RSA);  
	int b2 = (attestPub12->algorithmParms.encScheme != TPM_ES_NONE);  
	int b3 = (attestPub12->algorithmParms.sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1);  
	int b4 = (attestPub12->algorithmParms.parms.rsaParms.keyLength != 2048);  
	int b5 = (attestPub12->algorithmParms.parms.rsaParms.numPrimes != 2);  
	int b6 = (attestPub12->algorithmParms.parms.rsaParms.exponentSize != 0);  
	int b7 = (attestPub12->pubKey.keyLength != 256);
	if (b1 || b2 || b3 || b4 || b5 || b6 || b7) {
	    printf("ERROR: validateAttestationKey12: Invalid attest public key parameter\n");  
	    rc = ACE_INVALID_KEY;
	}
    }
    if (rc == 0) {
	if (verbose) printf("INFO: validateAttestationKey12: "
			    "Attestation key parameters are valid\n");
    }
    /* convert from TPM 1.2 to TPM 2.0 format for standard DB storage */
    if (rc == 0) {
	attestPub20->type = TPM_ALG_RSA;
	attestPub20->nameAlg = TPM_ALG_SHA1;
	attestPub20->objectAttributes.val = TPMA_OBJECT_SIGN | TPMA_OBJECT_RESTRICTED;
	attestPub20->authPolicy.t.size = 0;
	attestPub20->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	attestPub20->parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	attestPub20->parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
	attestPub20->parameters.rsaDetail.keyBits = 2048;
	attestPub20->parameters.rsaDetail.exponent = 0;
	attestPub20->unique.rsa.t.size = attestPub12->pubKey.keyLength;
	memcpy(attestPub20->unique.rsa.t.buffer,
	       attestPub12->pubKey.key, attestPub12->pubKey.keyLength);
    }
    free(attestPubBin);		/* @1 */
    return rc;
}

#endif

/* generateEnrollmentChallenge() generates the random server to client enrollment challenge.  It
   will be the input to make credential and the output of activate credential.
*/

static uint32_t generateEnrollmentChallenge(TPM2B_DIGEST *challenge,
					    char **challengeString)	/* freed by caller */
{
    uint32_t 	rc = 0;
    int		irc = 0;

    if (vverbose) printf("generateEnrollmentChallenge: Entry\n");

    /* generate a random AES-256 key */
    if (rc == 0) {
	challenge->t.size = 256/8;
	irc = RAND_bytes(challenge->t.buffer, 256/8);
	if (irc != 1) {
	    printf("ERROR: generateEnrollmentChallenge: Random number generation failed\n");
	    rc = ASE_OSSL_RAND;
	}
    }
    /* convert the challenge to string */
    if (rc == 0) {
	rc = Array_PrintMalloc(challengeString,		/* freed by caller */
			       challenge->t.buffer,
			       challenge->t.size);
    }
    if (rc == 0) {
	if (vverbose) TSS_PrintAll("processEnrollResponse: Challenge:",
				   challenge->t.buffer, challenge->t.size);
    }
    return rc;
}

/* generateAttestationCert() generates the attestation key certificate.  It is signed with the
   server privacy CA.

   It uses the client machine hostname as the subject common name.
*/

static uint32_t generateAttestationCert(char **akX509CertString,	/* freed by caller */
					char **akCertPemString,		/* freed by caller */
					uint8_t **attestCertBin,	/* freed by caller */
					uint32_t *attestCertBinLen,
					const char *hostname,
					TPMT_PUBLIC *attestPub)
{
    uint32_t rc = 0;

    /* FIXME should come from command line or config file */
    char *subjectEntries[] = {
	NULL,		/* 0 country */
	NULL,		/* 1 state */
	NULL,		/* 2 locality*/
	NULL,		/* 3 organization */
	NULL,		/* 4 organization unit */
	NULL,		/* 5 common name */
	NULL		/* 6 email */
    };
    /* FIXME should come from server privacy CA root certificate */
    char *issuerEntries[] = {
	"US"			,
	"NY"			,
	"Yorktown"		,
	"IBM"			,
	NULL			,
	"AK CA"			,
	NULL	
    };
    const char *pcaKeyPassword = PCA_PASSWORD;
    const char *pcaKeyFileName = PCA_KEY;

    if (vverbose) printf("generateAttestationCert: Entry\n");

    /* Precalculate the openssl nids */
    if (rc == 0) {
	rc = calculateNid();
    }
    /* the subject common name is the client hostname */
    if (rc == 0) {
	subjectEntries[5] = (char *)hostname;	
    }
    /* create the attestation key certificate from the attestation public key */
    if (rc == 0) {
	rc = createCertificate(akX509CertString,			/* freed by caller */
			       akCertPemString,				/* freed by caller */
			       attestCertBinLen,
			       attestCertBin,				/* output, freed by caller */
			       attestPub,
			       pcaKeyFileName,
			       sizeof(issuerEntries)/sizeof(char *),
			       issuerEntries,				/* certificate issuer */
			       sizeof(subjectEntries)/sizeof(char *),
			       subjectEntries,				/* certificate subject */
			       pcaKeyPassword);				/* privacy CA is RSA */
    }
    if (rc == 0) {
	if (vverbose) printf("generateAttestationCert: length %u\n", *attestCertBinLen);
    }
    return rc;
}

/* generateCredentialBlob() runs makecredential, wrap the challenge with the client EK public
   key, etc.  The command is run against a local server TPM.  It can be a SW TPM, since no secrets
   are used.

   ekPub - client EK public key
   attestPub - attestation public key
   challenge - server to client challenge
*/

static uint32_t generateCredentialBlob(char **credentialBlobString,	/* freed by caller */
				       TPM2B_ID_OBJECT *credentialBlob,
				       char **secretString,		/* freed by caller */
				       TPM2B_ENCRYPTED_SECRET *secret,
				       TPMT_PUBLIC *attestPub,
				       TPMT_PUBLIC *ekPub,
				       TPM2B_DIGEST *challenge)
{
    uint32_t 		rc = 0;
    TPM_HANDLE 		keyHandle = 0;	/* loaded key handle */
    
    if (vverbose) printf("generateCredentialBlob: Entry\n");
    
    /* Start a TSS context to a local, server TPM */
    TSS_CONTEXT 	*tssContext = NULL;
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* load the attestation public key.  This uses the TPM to calculate the Name. */
    TPM2B_NAME 		name;		/* attestation key Name */
    if (rc == 0) {
	rc = loadExternal(tssContext,
			  &keyHandle,	/* attestation key handle */
			  &name,		
			  attestPub);	/* attestation public key */
    }
    /* After the Name is returned, the loaded key is no longer needed. */
    if (keyHandle != 0) {
	rc = flushContext(tssContext,
			  keyHandle);
	keyHandle = 0;
    }
    /* load the EK public key, storage key used by makecredential */
    if (rc == 0) {
	rc = loadExternal(tssContext,
			  &keyHandle,	/* EK handle */
			  NULL,		/* don't need the Name */
			  ekPub);	/* client EK public key */
    }
    /* makecredential, encrypt the challenge, etc */
    if (rc == 0) {
	rc = makecredential(tssContext,
			    credentialBlob,
			    secret,
			    keyHandle,
			    challenge,
			    &name);
    }
    /* credentialBlob to string */
    if (rc == 0) {
	rc = Structure_Print(credentialBlobString,	/* freed by caller */
			     credentialBlob,
			     (MarshalFunction_t)TSS_TPM2B_ID_OBJECT_Marshalu);
    }
    /* secret to string */
    if (rc == 0) {
	rc = Structure_Print(secretString,		/* freed by caller */
			     secret,
			     (MarshalFunction_t)TSS_TPM2B_ENCRYPTED_SECRET_Marshalu);
    }
    /* done with the EK */
    if (keyHandle != 0) {
	rc = flushContext(tssContext,
			  keyHandle);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (verbose) printf("INFO: generateCredentialBlob: generated credential blob\n");
    }
    return rc;
}

#ifdef TPM_TPM12

/* generateCredentialBlob12() runs makecredential, wrap the challenge with the client EK public
   key, etc.  

   attestPub - attestation public key
   ekPub - client EK public key
   challenge - server to client challenge
*/

static uint32_t generateCredentialBlob12(uint8_t *encBlob,		/* hard coded 2048 bits */
					 size_t encBlobSize,
					 char **credentialBlobString,	/* freed by caller */
					 TPM_PUBKEY *attestPub,		/* attestation public key */
					 TPMT_PUBLIC *ekPub,		/* EK public key */
					 TPM2B_DIGEST *challenge)
{
    uint32_t 		rc = 0;

    TPM_EK_BLOB_ACTIVATE 	a1Activate;
    TPM_EK_BLOB			b1Blob;
    TPM_SYMMETRIC_KEY 		*k1SessionKey;

    /* create the TPM_SYMMETRIC_KEY sessionKey */
    if (rc == 0) {
	k1SessionKey = &a1Activate.sessionKey;	/* put directly in TPM_EK_BLOB_ACTIVATE */
	k1SessionKey->algId = TPM_ALG_AES128;
	k1SessionKey->encScheme = TPM_ES_SYM_CTR;
	k1SessionKey->size = sizeof(k1SessionKey->data);
	memcpy(k1SessionKey->data, challenge->t.buffer, k1SessionKey->size);
	if (verbose) TSS_PrintAll("generateCredentialBlob12: TPM_SYMMETRIC_KEY sessionKey",
				  k1SessionKey->data, k1SessionKey->size);
    }
    /* create the TPM_EK_BLOB_ACTIVATE */
    if (rc == 0) {
	a1Activate.tag = TPM_TAG_EK_BLOB_ACTIVATE; 
    }
    /* marshal the attestation TPM_PUBKEY before hashing */
    uint8_t aikPubkey[4096];	/* arbitrarily large */
    int aikPubLength;
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = aikPubkey;
	uint32_t size = sizeof(aikPubkey);	/* max size */
	rc = TSS_TPM_PUBKEY_Marshalu(attestPub, &written, &buffer, &size);
	aikPubLength = written;

    }
    /* hash the AIK TPM_PUBKEY and copy to idDigest */
    if (rc == 0) {
	TPMT_HA pubkeyHash;
	pubkeyHash.hashAlg = TPM_ALG_SHA1; 
	rc = TSS_Hash_Generate(&pubkeyHash,
			       aikPubLength, aikPubkey,
			       0, NULL);
	memcpy(a1Activate.idDigest, (uint8_t *)&pubkeyHash.digest, SHA1_DIGEST_SIZE);
	if (verbose) TSS_PrintAll("generateCredentialBlob12: TPM_EK_BLOB_ACTIVATE idDigest",
				  (uint8_t *)&pubkeyHash.digest, SHA1_DIGEST_SIZE);
    }
    if (rc == 0) {
	a1Activate.pcrInfo.pcrSelection.sizeOfSelect = 3;
	memset(a1Activate.pcrInfo.pcrSelection.pcrSelect,
	       0, a1Activate.pcrInfo.pcrSelection.sizeOfSelect);
	a1Activate.pcrInfo.localityAtRelease = TPM_LOC_ZERO;
    }
    /* create the TPM_EK_BLOB */
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = b1Blob.blob;
	uint32_t size = sizeof(b1Blob.blob);	/* max size */
	b1Blob.tag = TPM_TAG_EK_BLOB;
	b1Blob.ekType = TPM_EK_TYPE_ACTIVATE;
	b1Blob.blobSize = 0;
	rc = TSS_TPM_EK_BLOB_ACTIVATE_Marshalu(&a1Activate, &written, &buffer, &size);
	b1Blob.blobSize = written;
    }
    uint8_t 	decBlob[MAX_RSA_KEY_BYTES];
    size_t	decBlobLength;
    /* marshal the TPM_EK_BLOB */
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = decBlob;
	uint32_t size = sizeof(decBlob);	/* max size */
	rc = TSS_TPM_EK_BLOB_Marshalu(&b1Blob, &written, &buffer, &size);
	decBlobLength = written;
    }
    if (rc == 0) {
	if (decBlobLength > encBlobSize) {
	    printf("generateCredentialBlob12: TPM_EK_BLOB length %u too large\n",
		   (unsigned int)decBlobLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	if ((ekPub->parameters.rsaDetail.keyBits / 8) != encBlobSize) {
	    printf("generateCredentialBlob12: EK length %u not equal to %u\n",
		   ekPub->parameters.rsaDetail.keyBits / 8, (unsigned int)encBlobSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* encrypt the TPM_EK_BLOB */
    if (rc == 0) {
	if (verbose) TSS_PrintAll("generateCredentialBlob12: TPM_EK_BLOB",
				  decBlob, decBlobLength);
	/* public exponent */
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	/* encrypt the salt with the tpmKey public key */
	rc = TSS_RSAPublicEncrypt(encBlob,   		/* encrypted data */
				  encBlobSize,		/* size of encrypted data buffer */
				  decBlob, 		/* decrypted data */
				  decBlobLength,
				  ekPub->unique.rsa.t.buffer,  /* public modulus */
				  ekPub->unique.rsa.t.size,
				  earr, 		/* public exponent */
				  sizeof(earr),
				  (unsigned char *)"TCPA",	/* encoding parameter */
				  sizeof("TCPA")-1,	/* TPM 1.2 does not include NUL */
				  TPM_ALG_SHA1);	/* OAEP hash algorithm */
	if (verbose) TSS_PrintAll("generateCredentialBlob12: TPM_EK_BLOB encrypted",
				  encBlob, encBlobSize);
    }    
    /* credentialBlob to string */
    if (rc == 0) {
	rc = Array_PrintMalloc(credentialBlobString,		/* freed by caller */
			       encBlob, encBlobSize);
    }
    return rc; 
}

#endif
    
/* makecredential() runs TPM2_MakeCredential

 */

static uint32_t makecredential(TSS_CONTEXT *tssContext,
			       TPM2B_ID_OBJECT *credentialBlob,
			       TPM2B_ENCRYPTED_SECRET *secret,
			       TPM_HANDLE handle,
			       TPM2B_DIGEST *credential,
			       TPM2B_NAME *objectName)
{
    TPM_RC			rc = 0;
    MakeCredential_In 		makeCredentialIn;
    MakeCredential_Out 		makeCredentialOut;

    if (vverbose) printf("makecredential: Entry, handle %08x\n", handle);
    if (rc == 0) {
	makeCredentialIn.handle = handle;
	makeCredentialIn.credential = *credential;
	makeCredentialIn.objectName = *objectName;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&makeCredentialOut,
			 (COMMAND_PARAMETERS *)&makeCredentialIn,
			 NULL,
			 TPM_CC_MakeCredential,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*credentialBlob = makeCredentialOut.credentialBlob;
	*secret = makeCredentialOut.secret;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: makecredential: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}

/* getPubKeyFingerprint() gets the fingerprint, the X509 certificate Subject Key Identifier last 4
   bytes

*/

static uint32_t getPubKeyFingerprint(uint8_t *x509Fingerprint,
				     size_t fingerprintSize,
				     X509 *x509)
{
    uint32_t rc = 0;
    ASN1_OCTET_STRING *skid = NULL;

    /* get the subject key identifier from the X509 certificate */
    if (rc == 0) {
	skid = X509_get_ext_d2i(x509, NID_subject_key_identifier, NULL, NULL);
	if (skid == NULL) {
	    printf("ERROR: getPubKeyFingerprint: subject key identifier not found\n");
	    rc = 1;
	}
    }
    /* get the subject key identifier length */
    size_t skidLen;
    if (rc == 0) {
	skidLen = ASN1_STRING_length(skid);
	/* the SKID must be at least as big as the desired fingerprint size */
	if (skidLen < fingerprintSize) {
	    printf("ERROR: getPubKeyFingerprint: subject key identifier length %lu too small\n"
		   "\tmust be at least %lu\n",
		   skidLen, (unsigned long)fingerprintSize);
	    rc = 1;
	}
    }
    /* get the subject key identifier data */
    const uint8_t *skidData;
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	skidData = ASN1_STRING_data(skid);	/* deprecated in openssl 1.1 */
#else
	skidData = ASN1_STRING_get0_data(skid);	/* do not free */
#endif
	if (skidData == NULL) {
	    printf("ERROR: getPubKeyFingerprint: subject key identifier data is NULL\n");
	    rc = 1;
	}
    }
    /* fingerprint is the last fingerprintSize (4 for IMA) bytes */
    if (rc == 0) {
	if (vverbose) Array_Print(NULL, "getPubKeyFingerprint: Subject Key Identifier", TRUE,
				  skidData, skidLen);
	memcpy(x509Fingerprint, skidData + skidLen - fingerprintSize, fingerprintSize);
	if (vverbose) Array_Print(NULL, "getPubKeyFingerprint: certificate fingerprint", TRUE,
				  x509Fingerprint, fingerprintSize);
    }
    if (skid != NULL) {
	ASN1_OCTET_STRING_free(skid);
    }
    return rc;
}

/* verifyImaTemplateData() unmarshals the template data.

   If successful and vverbose, traces the template data.
*/

uint32_t verifyImaTemplateData(uint32_t *badEvent,	/* TRUE if template data parse error */
			       ImaTemplateData *imaTemplateData, /* unmarshaled template data */
			       int 	littleEndian,	/* boolean */
			       ImaEvent *imaEvent,	/* the current IMA event being processed */
			       int eventNum)	/* the current IMA event number being processed */
{
    uint32_t 	rc = 0;

    /* unmarshal the template data */
    if (rc == 0) {
	rc = IMA_TemplateData_ReadBuffer(imaTemplateData,
					 imaEvent,
					 littleEndian);
    }
    if (rc == 0) {
	if (vverbose) printf("verifyImaTemplateData: parsed template data, event %u\n", eventNum);
	*badEvent = FALSE;
	if (vverbose) IMA_TemplateData_Trace(imaTemplateData,
					     imaEvent->nameInt);
    }
    else {
	printf("ERROR: verifyImaTemplateData: error parsing template data, event %u\n",
	       eventNum);
	*badEvent = TRUE;
	rc = 0;		/* not a fatal error */
    }
    return rc;
}

/* verifyImaSigPresent() verifies the presence of a template data signature.

*/

uint32_t verifyImaSigPresent(uint32_t *noSig,		/* TRUE if no signature */
			     ImaTemplateData *imaTemplateData,	/* unmarshaled template data */
			     int eventNum)	/* the current IMA event number being processed */
{
    uint32_t 	rc = 0;

    if (imaTemplateData->imaTemplateSIG.sigLength != 0) {
	if (vverbose) printf("verifyImaSigPresent: found signature\n");
	*noSig = FALSE;
    }
    else {
	printf("ERROR: verifyImaSigPresent: missing signature, event %u\n", eventNum);
	*noSig = TRUE;
    }
    return rc;
}

/* getImaPublicKeyIndex() returns the index into the public key table corresponding to the
   fingerprint from the IMA template data

   Returns noKey TRUE if no matching key was found.
*/

uint32_t getImaPublicKeyIndex(uint32_t *noKey,
			      unsigned int *imaKeyNumber,
			      ImaTemplateData *imaTemplateData,	/* unmarshaled template data */
			      int eventNum)	/* the current IMA event number being processed */
{
    uint32_t 	rc = 0;
    int 	irc;

    *noKey	= TRUE;
    
    /* FIXME magic numbers */
    if (vverbose) Array_Print(NULL, "getImaPublicKeyIndex: required signature fingerprint", TRUE,
			      imaTemplateData->imaTemplateSIG.sigHeader + 3, 4);
    for (*imaKeyNumber = 0 ; (rc == 0) && (*imaKeyNumber < imaKeyCount) ; (*imaKeyNumber)++) {
	irc = memcmp(imaTemplateData->imaTemplateSIG.sigHeader + 3,
		     imaFingerprint[*imaKeyNumber], 4);
	if (irc == 0) {
	    if (vverbose) printf("getImaPublicKeyIndex: found public key at index %u\n",
				 *imaKeyNumber);
	    *noKey= FALSE;
	    break;
	}
    }
    if (*noKey) {
	printf("ERROR: getImaPublicKeyIndex: Error, no key for signature, event %u\n",
	       eventNum);
    }
    return rc;
}

/* verifyImaSignature() verifies the template data signature.

*/

uint32_t verifyImaSignature(uint32_t *badSig,
			    const ImaTemplateData *imaTemplateData,	/* unmarshaled template
									   data */
			    EVP_PKEY *evpPkey,	/* public key token, openssl format */
			    int eventNum)	/* the current IMA event number being processed */
{
    uint32_t 		rc = 0;
    TPMI_ALG_HASH 	halg;
    TPMT_SIGNATURE 	tSignature;

    if (rc == 0) {
	switch (imaTemplateData->imaTemplateDNG.hashAlgId) {
	  case TPM_ALG_SHA1:
	    halg = TPM_ALG_SHA1;
	    break;
	  case TPM_ALG_SHA256:
	    halg = TPM_ALG_SHA256;
	    break;
	  default:
	    printf("ERROR: verifyImaSignature: Error, bad algorithm identifier %04hx, event %u\n",
		   imaTemplateData->imaTemplateDNG.hashAlgId, eventNum);
	    *badSig = TRUE;
	}
    }
    if (rc == 0) {
	rc = convertRsaBinToTSignature(&tSignature,
				       halg,
				       imaTemplateData->imaTemplateSIG.signature,
				       imaTemplateData->imaTemplateSIG.signatureSize);
    }
    if (rc == 0) {
	rc = verifyRSASignatureFromRSA3(imaTemplateData->imaTemplateDNG.fileDataHash,
					imaTemplateData->imaTemplateDNG.fileDataHashLength,
					&tSignature,
					halg,
					evpPkey);
    }
    if (rc == 0) {
	if (verbose) printf("INFO: verifyImaSignature: signature verified, event %u\n",
				eventNum);
	*badSig = FALSE;

    }
    else {
	printf("ERROR: verifyImaSignature: Error, signature did not verify, event %u\n",
	       eventNum);
	*badSig = TRUE;
    }
    return 0;		/* always returns success, but sets badSig on failure */
}

/* getTimeStamp() reads the server machine time and converts to a timestamp string suitable for the
   SQL database */

static void getTimeStamp(char *timestamp, size_t size)
{
    time_t now = time(NULL);
    struct tm *timestampTm = localtime(&now);
    strftime(timestamp, size, "%Y-%m-%d %H:%M:%S", timestampTm);
    return;
}

#ifdef TPM_TPM12

/* isPrintableString() checks whether all characters in a string are printable */

static int isPrintableString(const uint8_t *string)
{
    size_t i;
    for (i = 0 ; i < strlen((const char *)string) ; i++) {
	if (!isprint(string[i])) {
	    return FALSE;
	}
    }
    return TRUE;
}

#endif

static void printUsage(void)
{
    printf("\n");
    printf("server\n");
    printf("\n");
    printf("Runs an attestation server\n");
    printf("\n");
    printf("-root filename contains list of TPM EK root PEM certificate file names\n");
    printf("-imacert filename contains DER encoded IMA verification certificates\n");
    printf("\t(may be specified up to %u times)\n", IMA_KEYS_MAX);
    printf("[-v verbose trace\n");
    printf("[-vv very verbose trace\n");
    printf("\n");
#ifdef ACS_BLOCKCHAIN
    printf("Blockchain environment variables\n");
    printf("\n");
    printf("\t[ACS_BC_SERVER - blockchain server name (default localhost)]\n");
    printf("\t[ACS_BC_PORT - blockchain server port (default 5000)]\n");
    printf("\t[ACS_BC_URL - blockchain server URL (default chaincode)]\n");
    printf("\n");
    printf("\tThat is, the default is http://localhost:5000/chaincode\n");
    printf("\tFor debug, typically use http://localhost:80/chaincode.php\n");
    printf("\n");
#endif
    exit(1);	
}
