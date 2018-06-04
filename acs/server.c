/********************************************************************************/
/*										*/
/*			TPM 2.0 Attestation - Server 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: server.c 1235 2018-05-30 20:05:39Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2018					*/
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

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <mysql/mysql.h>

#include <json/json.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssutils.h>
#include <tss2/tssprint.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsscrypto.h>
#include <tss2/tsscryptoh.h>

#if TPM_TPM12
#include <tss2/Unmarshal12_fp.h>
#include <tss2/tssmarshal12.h>
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
static void makePcrSelect(TPML_PCR_SELECTION *pcrSelection);
static uint32_t pcrStringToBin(unsigned char **pcrsSha1Bin,
			       size_t *pcrsSha1BinSize,
			       unsigned char **pcrsSha256Bin,
			       size_t *pcrsSha256BinSize,
			       const char *pcrsSha1String[],
			       const char *pcrsSha256String[]);
static uint32_t makePcrStream(unsigned char 	*pcrBinStream,
			      size_t 		*pcrBinStreamSize,
			      unsigned char 	**pcrsSha1Bin,
			      unsigned char 	**pcrsSha256Bin,
			      TPML_PCR_SELECTION *pcrSelection);
static uint32_t validatePcrs(const char *pcrsSha1String[],
			     const char *pcrsSha256String[],
			     TPMS_ATTEST *tpmsAttest);
static uint32_t checkBiosPCRsMatch(unsigned int *previousBiosPcrs,
				   unsigned int *biosPcrsMMatch,
				   MYSQL	*mysql,
				   const char	*quotePcrsSha256String[],
				   const char *hostname);
static uint32_t checkImaPCRsMatch(unsigned int	*imaPcrsMatch,
				  const char	*quotePcrsSha256String[],
				  const char 	*imapcr);
static uint32_t processBiosEntry(unsigned char **rspBuffer,
				 uint32_t *rspLength,
				 json_object *cmdJson);
static uint32_t processBiosEntryPass1(int *biosPcrVerified,
				      int *eventNum,
				      json_object *cmdJson,
				      uint8_t *quotePcrsBin[]);
static uint32_t processBiosEntryPass2(const char *hostname,
				      const char *timestamp,
				      json_object *cmdJson,
				      MYSQL *mysql);
static uint32_t processImaEntry(unsigned char **rspBuffer,
				uint32_t *rspLength,
				json_object *cmdJson);
static uint32_t processImaEntryPass1(uint32_t *crc,
				     int *imaPcrVerified,
				     unsigned int *eventNum,
				     json_object *cmdJson,
				     int tpm20,
				     uint8_t *previousImaPcr,
				     const uint8_t *currentImaPcr,
				     unsigned int imaEntry);
static uint32_t processImaEntryPass2(int *imasigver,
				     const char *machineName,
				     const char *boottime,
				     const char *timestamp,
				     json_object *cmdJson,
				     unsigned int imaEntry,
				     unsigned int lastEventNum,
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
			    RSA *rsaPkey,
			    int eventNum);

/* Support for TPM 1.2 */

#ifdef TPM_TPM12
static uint32_t processQuote12(unsigned char **rspBuffer,
			       uint32_t *rspLength,
			       json_object *cmdJson,
			       unsigned char *cmdBuffer);

static uint32_t checkBiosPCRsMatch12(unsigned int *previousBiosPcrs,
				     unsigned int *biosPcrsMMatch,
				     MYSQL	*mysql,
				     const char	*quotePcrsSha1String[],
				     const char *hostname);
static uint32_t processBiosEntry12Pass1(int *biosPcrVerified,
					int *eventNum,
					json_object *cmdJson,
					uint8_t *quotePcrsBin[]);
static uint32_t processBiosEntry12Pass2(const char *hostname,
					const char *timestamp,
					json_object *cmdJson,
					MYSQL *mysql);
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
static uint32_t checkImaPCRsMatch12(unsigned int	*imaPcrsMatch,
				    const char		*quotePcrsSha1String[],
				    const char 		*imapcr);
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
RSA		*imaRsaPkey[IMA_KEYS_MAX];

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
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
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
	    rc = getPubkeyFromDerCertFile(&imaRsaPkey[imaKeyNumber], &imaX509,
					  imaCertFilename[imaKeyNumber]);
	}
	/* get the fingerprint, the X509 certificate Subject Key Identifier last 4 bytes  for IMA */
	if (rc == 0) {
	    rc = getPubKeyFingerprint(imaFingerprint[imaKeyNumber],
				      sizeof(imaFingerprint[imaKeyNumber]), imaX509);
	}
	if (imaX509 != NULL) {
	    X509_free(imaX509);
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
	int connection_fd = -1;	
	unsigned char *cmdBuffer = NULL; 		  	/* command stream */
	uint32_t cmdLength;
	unsigned char *rspBuffer = NULL; 		  	/* command stream */
	uint32_t rspLength;

	if (rc == 0) {
	    rc = Socket_Connect(&connection_fd, sock_fd);
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
	Socket_Disconnect(&connection_fd);
	free(cmdBuffer);			/* @1 */
	cmdBuffer = NULL;
	free(rspBuffer);			/* @2 */
	rspBuffer = NULL;
	rc = 0;
    }
    return rc;
}

/* processRequest() is the entry point for all client requests.

   The client command is in cmdBuffer, and the client response is put in the allocated rspBuffer.
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
	/* bios measurements */
	else if ((strcmp(commandString, "biosentry") == 0) ||
		 (strcmp(commandString, "biosentry12") == 0)) {
	    if (vverbose) printf("processRequest: processing biosentry\n");
	    rc = processBiosEntry(rspBuffer,		/* freed by caller */
				  rspLength,
				  cmdJson);
	}
	/* ima measurements */
	else if ((strcmp(commandString, "imaentry") == 0) ||
		 (strcmp(commandString, "imaentry12") == 0)) {
	    if (vverbose) printf("processRequest: processing imaentry\n");
	    rc = processImaEntry(rspBuffer,
				 rspLength,
				 cmdJson);
	}
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
	else {
	    printf("ERROR: processRequest: command %s unknown \n", commandString);
	    rc = processSendError(rspBuffer,		/* freed by caller */
				  rspLength,
				  ACE_UNKNOWN_CMD);

	}
	/* if construction of response packet failed, try constructing response json explicitly. */
	if (rc != 0) {
	    printf("ERROR: processRequest: server could not construct response json\n");
	    free(*rspBuffer);
	    *rspBuffer = NULL;
	    rc = processSendError(rspBuffer,		/* freed by caller */
				  rspLength,
				  ASE_NO_RESPONSE);
	}
    }
    /* json command parse error */
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

*/

static uint32_t processSendError(unsigned char **rspBuffer,		/* freed by caller */
				 uint32_t *rspLength,
				 uint32_t errorCode)
{
    uint32_t  	rc = 0;
    
    /* create the error return json */
    json_object *response = NULL;
    rc = JS_ObjectNew(&response);	/* freed @1 */
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
   "hostname":"cainl.watson.ibm.com",
   "userid":"kgold"
   }

   ~~
   
   It creates an attestlog DB entry for this client attestation, with:

   userid - the client user name
   hostname - the client machine name
   timestamp - server time
   nonce - generated on the server
   pcrselect - ACS uses all SHA-256 PCR 0-7 for BIOS event log and PCR 10 SHA-256 for IMA event log.

   ~~

   The client response is of the form:

   {
   "response":"nonce",
   "nonce":"9c0fe9df6b609dd753530ecda1bfb1e6a7d32460ddb8e36c35f028281b7d8c5d",
   "pcrselect":"00000002000b03ff0400000403000000"
   }
*/

static uint32_t processNonce(unsigned char **rspBuffer,		/* freed by caller */
			     uint32_t *rspLength,
			     json_object *cmdJson)
{
    uint32_t  	rc = 0;
    int		irc = 0;

    unsigned char nonceBinary[SHA256_DIGEST_SIZE];

    if (verbose) printf("INFO: processNonce: Entry\n");
    /* get the command, nonce for TPM 2.0 and nonce12 for TPM 1.2 */
    const char *commandString;
    if (rc == 0) {
	rc = JS_ObjectGetString(&commandString, "command", cmdJson);
    }
    /* get the client machine name from the command */
    const char *hostname = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* get the client user name from the command - userid in ACS terms */
    const char *userid = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&userid, "userid", cmdJson);
    }
    /* connect to the db */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @1 */	
    }
    /* get the DB information for this machine, verify that machine is enrolled */
    MYSQL_RES 		*machineResult = NULL;
    if (rc == 0) {
	const char 		*akCertificatePem = NULL;
	rc = SQ_GetMachineEntry(NULL, 			/* machineId */
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
	SQ_FreeResult(machineResult);			/* @2 */
    }    
    /* generate binary nonce for the client attestation */
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
	    makePcrSelect(&pcrSelection);
	    rc = Structure_Print(&pcrSelectionString,		/* freed @5 */
				 &pcrSelection,
				 (MarshalFunction_t)TSS_TPML_PCR_SELECTION_Marshal);
#ifdef TPM_TPM12
	}
	else {		/* TPM 1.2 */
	    uint32_t valueSize;
	    TPM_PCR_SELECTION pcrSelection;
	    makePcrSelect12(& valueSize, &pcrSelection);
	    rc = Structure_Print(&pcrSelectionString,		/* freed @5 */
				 &pcrSelection,
				 (MarshalFunction_t)TSS_TPM_PCR_SELECTION_Marshal);
	}
#endif
    }
    /* copy the nonce to the new db entry for later compare */
    char query[QUERY_LENGTH_MAX];
    /* create a new db entry, quoteverified is NULL, indicating nonce has not been used */
    if (rc == 0) {
	sprintf(query,
		"insert into attestlog "
		"(userid, hostname, timestamp, nonce, pcrselect) "
		"values ('%s','%s','%s','%s','%s')",
		userid, hostname, timestamp, nonceString, pcrSelectionString);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* create the nonce return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);	/* freed @6 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response",
				   json_object_new_string("nonce"));
	    json_object_object_add(response, "nonce",
				   json_object_new_string(nonceString));
	    json_object_object_add(response, "pcrselect",
				   json_object_new_string(pcrSelectionString));
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
    free(nonceString);			/* @3 */
    free(pcrSelectionString);		/* @5 */
    return rc;
}

/* processQuote() processes the client quote and creates the client response.

   The client command is:

   {
   "command":"quote",
   "hostname":"cainl.watson.ibm.com",
   "boottime":"2016-03-21 09:08:25",
   "pcr0shan":"hexascii",
   ...
   "pcr23shan":"hexascii",
   "quoted":"hexascii",
   "signature":"hexascii",
   }

   The server response is this if BIOS PCRs match:
     
   {
   "response":"quote"
   "biosentry":"0"
   "imaentry":"0"
   }
     
   0 full log starting with entry 0
   >0 incremental log starting at that number
   -1 no log
   
   ~~

   Initializes the machines PCR white list

   Initializes the machines imaevents, imapcr, boottime

   Updates the attestlog

   - pcrs changed
   - quote pcrs
   - pcrs invalid vs white list
   - quote verified
   - boottime 

*/

/* NOTE Future enhancement: don't ask for event logs if BIOS PCRs did not change */

static uint32_t processQuote(unsigned char **rspBuffer,		/* freed by caller */
			     uint32_t *rspLength,
			     json_object *cmdJson,
			     unsigned char *cmdBuffer)
{
    uint32_t  		rc = 0;	
    int 		irc = 0;
    unsigned char 	*tmpptr;	/* so actual pointers don't move */
    uint32_t		tmpsize;

    /* from client */
    const char 		*hostname = NULL;
    const char 		*clientBoottime = NULL;
    const char 		*quotePcrsSha1String[IMPLEMENTATION_PCR];
    const char 		*quotePcrsSha256String[IMPLEMENTATION_PCR];
    const char 		*quoted = NULL;
    unsigned char 	*quotedBin = NULL;
    size_t 		quotedBinSize;
    const char 		*signature = NULL;
    unsigned char 	*signatureBin = NULL;
    size_t 		signatureBinSize;
    unsigned int 	pcrNum;

    /* status flags */
    unsigned int 	quoteVerified = FALSE;	/* TRUE if quote signature verified AND PCRs match
						   quote digest AND nonce matches */
    unsigned int 	biosPcrsMatch = FALSE; /* TRUE if previous valid quote and PCRs did not
						  change */
    unsigned int	previousBiosPcrs = FALSE;	/* TRUE is there was a previous valid
							   quote */
    unsigned int 	imaPcrsMatch = FALSE;		/* TRUE if previous valid quote and IMA PCR
							    did not change */
    unsigned int 	storePcrWhiteList = FALSE;	/* flag to store first PCR values in
							   machines DB */
    unsigned int 	pcrinvalid = FALSE;	/* from first valid quote, only meaningful if
						   storePcrWhiteList is FALSE */

    if (vverbose) printf("INFO: processQuote: Entry\n");
    /*
      Get data from client command json
    */
    /* Get the client hostname.  Do this first since this DB column should be valid. */
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* Get the client boottime. */
    if (rc == 0) {
	rc = JS_ObjectGetString(&clientBoottime, "boottime", cmdJson);
    }
    /* client reports its PCRs */
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	rc = JS_Cmd_GetPCR(&quotePcrsSha1String[pcrNum],
			   &quotePcrsSha256String[pcrNum],
			   pcrNum,
			   cmdJson);
    }
    /* Get the client quoted data */
    if (rc == 0) {
	rc = JS_ObjectGetString(&quoted, "quoted", cmdJson);
    }
    /* convert the quoted to binary */
    if (rc == 0) {
	rc = Array_Scan(&quotedBin ,	/* output binary, freed @1 */
			&quotedBinSize,
			quoted);	/* input string */
    }    
    /* Get the client quote signature */
    if (rc == 0) {
	rc = JS_ObjectGetString(&signature, "signature", cmdJson);
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
	rc = TPMT_SIGNATURE_Unmarshal(&tpmtSignature, &tmpptr, &tmpsize, TRUE);
    }
    /* read the nonce from the attestlog based on the hostname */
    MYSQL *mysql = NULL;
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @3 */	
    }
    /* in machines db, select id, certificate, boottime using hostname and active
       in attestlog, select hostname, order by id, get nonce, pcrselect
    */
    MYSQL_RES 		*machineResult = NULL;
    char 		*machineId = NULL;	/* row being updated */
    const char 		*akCertificatePem = NULL;
    const char 		*boottime = NULL;
    int 		imaevents;
    int 		biosevents;
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
				&boottime,		/* boottime */
				&imaevents,		/* imaevents */
				&imapcr,		/* imapcr */
				&machineResult,		/* freed @7 */
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
    /* in attestlog, select hostname, order by id, get nonce */
    /* get the attestlog row being updated.  Row was inserted at processNonce.  If the row does not
       exist, fatal client error */
    MYSQL_RES 		*attestLogResult = NULL;
    char 		*attestLogId = NULL;	/* row being updated */
    const char 		*nonceServerString = NULL;	/* nonce from server DB */
    const char 		*quoteVerifiedString = NULL;	/* boolean from server DB */
    if (rc == 0) {
	/* this is a client error, indicating a bad hostname, or a hostname for the first time and
	   no nonce was requested. */
	rc = SQ_GetAttestLogEntry(&attestLogId, 		/* freed @5 */
				  NULL,				/* boottime */
				  NULL,				/* timestamp */
				  &nonceServerString,		/* nonce */
				  NULL,				/* pcrselect */
				  &quoteVerifiedString,		/* quoteverified */
				  NULL,				/* logverified */
				  &attestLogResult,		/* freed @4 */
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
	    printf("ERROR: processQuote: nonce for hostname %s already used\n", hostname);  
	    rc = ACE_NONCE_USED;
	}
	else {
	    if (verbose) printf("INFO: processQuote: found attestlog DB entry for %s\n", hostname);  
	}
    }
    /*
      Validate the quote signature
    */
    /* SHA-256 hash the quoted */
    TPMT_HA digest;
    if (rc == 0) {
	if (vverbose) printf("processQuote: quotedBinSize %lu\n", quotedBinSize);
	if (vverbose) Array_Print(NULL, "processQuote: quotedBin", TRUE,
				  quotedBin, quotedBinSize);
	digest.hashAlg = TPM_ALG_SHA256;
	rc = TSS_Hash_Generate(&digest,
			       quotedBinSize, quotedBin,
			       0, NULL);
    }
    if (rc == 0) {
	if (vverbose) Array_Print(NULL, "processQuote: quoteMessage", TRUE,
				  (uint8_t *)&digest.digest, SHA256_DIGEST_SIZE);
	if (vverbose) Array_Print(NULL, "processQuote: signature", TRUE,
				  tpmtSignature.signature.rsassa.sig.t.buffer,
				  tpmtSignature.signature.rsassa.sig.t.size);
    }
    X509 		*x509 = NULL;		/* public key */
    /* convert the quote verification PEM certificate to X509 */
    if (rc == 0) {
	rc = convertPemMemToX509(&x509,			/* freed @11 */
				 akCertificatePem);
    }
    if (tpmtSignature.sigAlg == TPM_ALG_RSASSA) {
	RSA  		*rsaPkey = NULL;
	/* extract the RSA key token from the X509 certificate */
	if (rc == 0) {
	    rc = convertX509ToRsa(&rsaPkey,			/* freed @10 */
				  x509);
	}
	/* verify the quote signature against the hash of the TPM_QUOTE_INFO */
	if (rc == 0) {
	    irc = RSA_verify(NID_sha256,
			     (uint8_t *)&digest.digest, SHA256_DIGEST_SIZE,
			     tpmtSignature.signature.rsassa.sig.t.buffer,
			     tpmtSignature.signature.rsassa.sig.t.size,
			     rsaPkey);
	    if (irc != 1) {		/* quote signature did not verify */
		rc = ACE_QUOTE_SIGNATURE;	/* skip reset of the tests */
		quoteVerified = FALSE;	/* remains false */
		printf("ERROR: processQuote: Signature verification failed\n");
	    }
	    else {
		quoteVerified = TRUE;	/* tentative */
		if (verbose) printf("INFO: processQuote: quote signature verified\n");
	    }
	}
	if (rsaPkey != NULL) {
	    RSA_free(rsaPkey);		/* @10 */
	}
    }
    else if (tpmtSignature.sigAlg == TPM_ALG_ECDSA) {
	int irc;
	EC_KEY *ecKey = NULL;
	/* extract the EC key token from the X509 certificate */
	if (rc == 0) {
	    rc = convertX509ToEc(&ecKey,			/* freed @10 */
				 x509);
	}
	/* construct the ECDSA_SIG signature token */
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	if (rc == 0) {
	    rc = convertBin2Bn(&r,			/* freed @11 */
			       tpmtSignature.signature.ecdsa.signatureR.t.buffer,
			       tpmtSignature.signature.ecdsa.signatureR.t.size);
	}	
	if (rc == 0) {
	    rc = convertBin2Bn(&s,			/* freed @11 */
			       tpmtSignature.signature.ecdsa.signatureS.t.buffer,
			       tpmtSignature.signature.ecdsa.signatureS.t.size);
	}	
	ECDSA_SIG *ecdsaSig;
	if (rc == 0) {
	    ecdsaSig = ECDSA_SIG_new();			/* freed @11 */
	    if (ecdsaSig == NULL) {
		printf("ERROR: processQuote: ECDSA_SIG_new() failed\n");  
		rc = ASE_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	    ecdsaSig->r = r;
	    ecdsaSig->s = s;
#else
	    /* alling this function transfers the memory management of the values to the DSA_SIG
	       object, and therefore the values that have been passed in should not be freed
	       directly after this function has been called. */
	    irc = ECDSA_SIG_set0(ecdsaSig, r, s);
	    if (irc != 1) {
		printf("ERROR: processQuote: ECDSA_SIG_set0() failed\n");  
		rc = ACE_OSSL_ECC;
	    }
#endif
	}
	if (rc == 0) {
	    irc = ECDSA_do_verify((uint8_t *)&digest.digest, SHA256_DIGEST_SIZE, 
				  ecdsaSig, ecKey);
	    if (irc != 1) {		/* quote signature did not verify */
		rc = ACE_QUOTE_SIGNATURE;	/* skip reset of the tests */
		quoteVerified = FALSE;	/* remains false */
		printf("ERROR: processQuote: Signature verification failed\n");
	    }
	    else {
		quoteVerified = TRUE;	/* tentative */
		if (verbose) printf("INFO: processQuote: quote signature verified\n");
	    }
	}
	if (ecKey != NULL) {
	    EC_KEY_free(ecKey);		/* @10 */
	}
	if (ecdsaSig != NULL) {
	    ECDSA_SIG_free(ecdsaSig);	/* @11 */
	}
    }
    else {
	if (rc == 0) {
	    printf("ERROR: processQuote: Invalid signature algotithm \n");
	}
    }
    /* unmarshal the TPM2B_ATTEST quoted structure */
    TPMS_ATTEST tpmsAttest;
    if (rc == 0) {
	tmpptr = quotedBin;		/* so actual pointers don't move */
	tmpsize= quotedBinSize;
	rc = TPMS_ATTEST_Unmarshal(&tpmsAttest, &tmpptr, &tmpsize);
	if (rc != 0) {
	    printf("ERROR: processQuote: cannot unmarshal client quoted structure\n");  
	}
    }
    /* validate the PCR values from the client against their hash in the signed quote.  Also
       validate that the PCR selection from the client is the same as the requested selection from
       the server. */
    if (rc == 0) {
	rc = validatePcrs(quotePcrsSha1String,
			  quotePcrsSha256String,
			  &tpmsAttest);
	if (rc != 0) {
	    rc = ACE_PCR_VALUE;	/* skip reset of the tests */
	    quoteVerified = FALSE;
	    printf("ERROR: processQuote: PCR verification failed\n");
	}
	else {
	    quoteVerified = TRUE;
	    if (verbose) printf("INFO: processQuote: PCRs match quote data\n");
	}
    }
    /*
      validate that the nonce / extraData in the quoted is what was supplied to the client
    */
    /* convert the server nonce to binary, server error since the nonce should have been inserted
       correctly */
    unsigned char 	*nonceServerBin = NULL;
    size_t 		nonceServerBinSize;
    if (rc == 0) {
	rc = Array_Scan(&nonceServerBin,	/* output binary, freed @8 */
			&nonceServerBinSize,
			nonceServerString);	/* input string */
    }
    /* check nonce sizes */
    if (rc == 0) {
	if (nonceServerBinSize != tpmsAttest.extraData.t.size) {
	    printf("ERROR: processQuote: nonce size mismatch, server %lu client %u\n",
		   nonceServerBinSize, tpmsAttest.extraData.t.size);
	    rc = ACE_NONCE_LENGTH;
	}
    }
    /* compare to the server nonce to the client nonce from the quoted */
    if (rc == 0) {
	if (memcmp(nonceServerBin, &tpmsAttest.extraData.t.buffer, nonceServerBinSize) != 0) {
	    rc = ACE_NONCE_VALUE;
	    quoteVerified = FALSE;	/* quote nonce */
	    printf("ERROR: processQuote: client nonce does not match server database\n");  
	}
	else {
	    quoteVerified = TRUE;
	    if (verbose) printf("INFO: processQuote: client nonce matches server database\n");  
	}
    }
    /*
      Processing once the quote is verified completely, (rc is still 0)
    */
    SQ_FreeResult(attestLogResult);			/* @4 */
    attestLogResult = NULL;
    /* determine whether BIOS PCRs match the previous quote. If no previous quote, PCRs do not
       match.  */
    if (rc == 0) {
	if (verbose) printf("INFO: processQuote: Check previous BIOS PCRs\n");  
	rc = checkBiosPCRsMatch(&previousBiosPcrs,
				&biosPcrsMatch,
				mysql,
				quotePcrsSha256String,
				hostname);
	if (biosPcrsMatch) {
	    biosevents = -1;		/* BIOS event log not needed */
	}
	else {
	    biosevents = 0;		/* BIOS event is always full, not incremental */
	}
    }
    /* if the BIOS PCRs did not change, determine if the IMA PCR changed */
    if ((rc == 0) && biosPcrsMatch) {
	if (verbose) printf("INFO: processQuote: Check previous IMA PCRs\n");  
	rc = checkImaPCRsMatch(&imaPcrsMatch,
			       quotePcrsSha256String,
			       imapcr);
	if (imaPcrsMatch) {
	    imaevents = -1;
	}
    }
    /* get PCRs from the first attestation, this is the white list */
    const char *firstPcrsSha1String[IMPLEMENTATION_PCR];
    const char *firstPcrsSha256String[IMPLEMENTATION_PCR];
    if (rc == 0) {
	rc = SQ_GetFirstPcrs(firstPcrsSha1String,
			     firstPcrsSha256String,
			     &machineResult,		/* freed @7 */
			     mysql,
			     hostname);
	/* no PCR white list */
	if ((firstPcrsSha256String[0] == NULL) && quoteVerified) {
	    /* store the first quote PCRs in the machines table as a white list */
	    storePcrWhiteList = TRUE;	/* flag, store it in machines DB */
	}
    }
    /* if there were first values, use as white list, check if any changed */
    if ((rc == 0) && !storePcrWhiteList && quoteVerified) {
	if (vverbose) printf("processQuote: validate quote BIOS PCRs vs. white list\n");  
	for (pcrNum = 0 ; (pcrNum < 8) && !pcrinvalid ; pcrNum++) {
	    irc = strcmp(firstPcrsSha256String[pcrNum], quotePcrsSha256String[pcrNum]);
	    if (irc != 0) {
		if (verbose) printf("INFO: processQuote: PCR %02u invalid\n", pcrNum);  
		if (verbose) printf("INFO: processQuote: current PCR %s\n",
				    quotePcrsSha256String[pcrNum]);
		if (verbose) printf("INFO: processQuote: valid   PCR %s\n",
				    firstPcrsSha256String[pcrNum]);
		pcrinvalid = TRUE;
		break;
	    }
	}
	if (!pcrinvalid) {
	    if (verbose) printf("INFO: processQuote: quote PCRs match white list\n");
	}
	else {
	    if (verbose) printf("INFO: processQuote: quote PCRs do not match white list\n");
	}
    }
    /*
      store the results in DB
    */
    char query[QUERY_LENGTH_MAX];
    /*
      machines table
    */
    /* first time, write PCR white list, if quote did not verify, don't store counterfeit PCR
       values */
    if (verbose && (rc == 0) && storePcrWhiteList)
	printf("INFO: processQuote: store PCR white list\n");
    for (pcrNum = 0 ;
	 (rc == 0) && storePcrWhiteList && (machineId != NULL) && (pcrNum < IMPLEMENTATION_PCR) ;
	 pcrNum++) {
	
	sprintf(query,
		"update machines set pcr%02usha1 = '%s' where id = '%s'",
		pcrNum, quotePcrsSha1String[pcrNum], machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
	sprintf(query,
		"update machines set pcr%02usha256 = '%s' where id = '%s'",
		pcrNum, quotePcrsSha256String[pcrNum], machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* first time, or new boot cycle, reset imaevents (next event to be processed) */
    if ((rc == 0) && (machineId != NULL)) {
	int irc = 0;
	if (!storePcrWhiteList) {
	    irc = strcmp(boottime, clientBoottime);	/* is this a new client boot cycle */
	}
	if (storePcrWhiteList || (irc != 0)) {
	    if (verbose) printf("INFO: processQuote: new boot cycle, reset imaevents\n");
	    imaevents = 0;
	    /* reset the imaevents counter, indicates a reboot to the next step, hard code to
	       SHA-256 */
	    sprintf(query,
		    "update machines set imaevents = '%u', imapcr = '%s' where id = '%s'",
		    imaevents, "0000000000000000000000000000000000000000000000000000000000000000",
		    machineId);
	    rc = SQ_Query(NULL,
			  mysql, query);
	}
    }
    /* boottime to machines */
    if ((rc == 0) && (machineId != NULL)) {
	if (verbose) printf("INFO: processQuote: store boottime %s\n", clientBoottime);
	sprintf(query,
		"update machines set boottime = '%s' where id = '%s'",
		clientBoottime, machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /*
      attestlog table
    */
    /* PCRs change from previous value, only if quoteverified, rc is 0, and there were previous PCRs */
    if ((rc == 0) && previousBiosPcrs && (attestLogId != NULL)) {
	sprintf(query,
		"update attestlog set pcrschanged = '%u' where id = '%s'",
		!biosPcrsMatch, attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* write quote PCRs, only if quoteverified, rc is 0 */
    for (pcrNum = 0 ;
	 (rc == 0) && (attestLogId != NULL) && (pcrNum < IMPLEMENTATION_PCR) ;
	 pcrNum++) {
	
	sprintf(query,
		"update attestlog set pcr%02usha1 = '%s' where id = '%s'",
		pcrNum, quotePcrsSha1String[pcrNum], attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
	sprintf(query,
		"update attestlog set pcr%02usha256 = '%s' where id = '%s'",
		pcrNum, quotePcrsSha256String[pcrNum], attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* PCRs invalid vs white list (only if there was a white list) */
    if ((rc == 0) && !storePcrWhiteList && (attestLogId != NULL)) {
	sprintf(query,
		"update attestlog set pcrinvalid = '%u' where id = '%s'",
		pcrinvalid, attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* quoteVerified */
    uint32_t rc2;
    if (attestLogId != NULL) {
	sprintf(query,
		"update attestlog set quoteverified = '%u' where id = '%s'",
		quoteVerified, attestLogId);
	rc2 = SQ_Query(NULL,
		       mysql, query);
	if (rc == 0) {
	    rc = rc2;
	}
    }
    /* boottime to attestlog */
    /* add raw quoted data to attestlog */
    if (attestLogId != NULL) {
	sprintf(query,
		"update attestlog set boottime = '%s', quote = '%s' where id = '%s'",
		clientBoottime, cmdBuffer, attestLogId);
	rc2 = SQ_Query(NULL,
		       mysql, query);
	if (rc == 0) {
	    rc = rc2;
	}
    }
    /*
      create the quote return json
    */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @9 */
    if (rc1 == 0) {
	char eventsString[16];
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("quote"));
	}
	if (rc == 0) {
	    sprintf(eventsString, "%d", biosevents);
	    json_object_object_add(response, "biosentry",
				   json_object_new_string(eventsString));
	}
	if (rc == 0) {
	    sprintf(eventsString, "%d", imaevents);
	    json_object_object_add(response, "imaentry",
				   json_object_new_string(eventsString));
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
    SQ_FreeResult(attestLogResult);	/* @4 */
    free(attestLogId);			/* @5 */
    free(machineId);			/* @6 */
    SQ_FreeResult(machineResult);	/* @7 */
    free(nonceServerBin);		/* @8 */
    if (x509 != NULL) {
	X509_free(x509);		/* @11 */
    }
    return rc;
}

#ifdef TPM_TPM12

/* processQuote12 processes the client quote and creates the client response.

   The client command is:

   {
   "command":"quote12",
   "hostname":"cainl.watson.ibm.com",
   "boottime":"2016-03-21 09:08:25",
   "pcr0sha1":"hexascii",
   ...
   "pcr23sha1":"hexascii",
   "pcrdata":"hexascii",
   "versioninfo":"hexascii",
   "signature":"hexascii",
   }

   The server response is this if BIOS PCRs match:
     
   {
   "response":"quote"
   "biosentry":"0"
   "imaentry":"0"
   }
     
   0 full log starting with entry 0
   >0 incremental log starting at that number
   -1 no log
   
   ~~

   Initializes the machines PCR white list

   Initializes the machines imaevents, imapcr, boottime

   Updates the attestlog

   - pcrs changed
   - quote pcrs
   - pcrs invalid vs white list
   - quote verified
   - boottime 

*/

/*  processQuote12() verifies the quote signature and the received PCRs.  On a first attestation,
    stores the white list.  On subsequent attestations, verifies the PCRs against that white list.

    If the PCRs changed, asks for the BIOS or IMA event log.

*/

static uint32_t processQuote12(unsigned char **rspBuffer,		/* freed by caller */
			       uint32_t *rspLength,
			       json_object *cmdJson,
			       unsigned char *cmdBuffer)
{
    uint32_t  		rc = 0;	
    int 		irc = 0;
    /* from client */
    const char 		*hostname = NULL;
    const char 		*clientBoottime = NULL;
    const char 		*quotePcrsSha1String[IMPLEMENTATION_PCR];	/* string from json */
    unsigned char 	*quotePcrsSha1Bin[IMPLEMENTATION_PCR];
    size_t 		quotePcrsSha1BinSize[IMPLEMENTATION_PCR];
    const char 		*pcrDataString = NULL;	/* string from json */
    unsigned char 	*pcrDataBin = NULL;
    size_t 		pcrDataBinSize;
    const char 		*versionInfo = NULL;	/* string from json */
    unsigned char 	*versionInfoBin = NULL;
    size_t 		versionInfoBinSize;
    const char 		*signature = NULL;	/* string from json */
    unsigned char 	*signatureBin = NULL;
    size_t 		signatureBinSize;
    unsigned int 	pcrNum;

    /* status flags */
    unsigned int 	quoteVerified = FALSE;	/* TRUE if quote signature verified AND PCRs match
						   quote digest AND nonce matches */
    unsigned int 	biosPcrsMatch = FALSE; 	/* TRUE if previous valid quote and PCRs did not
						   change */
    unsigned int	previousBiosPcrs = FALSE;	/* TRUE is there was a previous valid
							   quote */
    unsigned int 	imaPcrsMatch = FALSE; 		/* TRUE if previous valid quote and IMA PCR
							   did not change */
    unsigned int 	storePcrWhiteList = FALSE;	/* flag to store first PCR values in
							   machines DB */
    unsigned int 	pcrinvalid = FALSE;	/* from first valid quote, only meaningful if
						   storePcrWhiteList is FALSE */

    if (vverbose) printf("INFO: processQuote12: Entry\n");
    /*
      Get data from client command json
    */
    /* Get the client hostname.  Do this first since this DB column should be valid. */
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* Get the client boottime. */
    if (rc == 0) {
	rc = JS_ObjectGetString(&clientBoottime, "boottime", cmdJson);
    }
    /* client reports its PCRs */
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	rc = JS_Cmd_GetPCR(&quotePcrsSha1String[pcrNum],
			   NULL,	/* TPM 1.2 does not have SHA-256 */
			   pcrNum,
			   cmdJson);
    }
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	quotePcrsSha1Bin[pcrNum] = NULL;	/* for safe free */
    }
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (rc == 0) {
	    rc = Array_Scan(&quotePcrsSha1Bin[pcrNum],	/* output binary, freed @1 */
			    &quotePcrsSha1BinSize[pcrNum],
			    quotePcrsSha1String[pcrNum]);	/* input string */
	}
	if (rc == 0) {
	    if (quotePcrsSha1BinSize[pcrNum] != SHA1_DIGEST_SIZE) {
		printf("ERROR: processQuote12: PCR %u size %lu not SHA-1\n",
		       pcrNum, (unsigned long)quotePcrsSha1BinSize[pcrNum]);  
		rc = ACE_PCR_LENGTH;
	    }
	}	
    }
    /* Get the client pcrdata */
    if (rc == 0) {
	rc = JS_ObjectGetString(&pcrDataString, "pcrdata", cmdJson);
    }
    /* convert the pcrdata to binary */
    if (rc == 0) {
	rc = Array_Scan(&pcrDataBin ,		/* output binary, freed @2 */
			&pcrDataBinSize,
			pcrDataString);		/* input string */
    }    
    /* Get the client versionInfo */
    if (rc == 0) {
	rc = JS_ObjectGetString(&versionInfo, "versioninfo", cmdJson);
    }
    /* convert the versionInfo to binary */
    if (rc == 0) {
	rc = Array_Scan(&versionInfoBin ,	/* output binary, freed @3 */
			&versionInfoBinSize,
			versionInfo);		/* input string */
    }    
    /* Get the client quote signature */
    if (rc == 0) {
	rc = JS_ObjectGetString(&signature, "signature", cmdJson);
    }
    /* convert the signature to binary */
    if (rc == 0) {
	rc = Array_Scan(&signatureBin,	/* output binary, freed @4 */
			&signatureBinSize ,
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
    char 		*machineId = NULL;	/* row being updated */
    const char 		*akCertificatePem = NULL;
    const char 		*boottime = NULL;
    int 		imaevents;
    int 		biosevents;
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
				&boottime,		/* boottime */
				&imaevents,		/* imaevents */
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
    /* in attestlog, select hostname, order by id, get nonce */
    /* get the attestlog row being updated.  Row was inserted at processNonce.  If the row does not
       exist, fatal client error */
    MYSQL_RES 		*attestLogResult = NULL;
    char 		*attestLogId = NULL;		/* row being updated */
    const char 		*nonceServerString = NULL;	/* nonce from server DB */
    const char 		*quoteVerifiedString = NULL;	/* boolean from server DB */
    if (rc == 0) {
	/* this is a client error, indicating a bad hostname, or a hostname for the first time and
	   no nonce was requested. */
	rc = SQ_GetAttestLogEntry(&attestLogId, 		/* freed @8 */
				  NULL,				/* boottime */
				  NULL,				/* timestamp */
				  &nonceServerString,		/* nonce */
				  NULL,				/* pcrselect */
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
    /*
      Validate the quote signature
    */
    /* convert the server nonce to binary, server error since the nonce should have been inserted
       correctly */
    unsigned char 	*nonceServerBin = NULL;
    size_t 		nonceServerBinSize;
    if (rc == 0) {
	rc = Array_Scan(&nonceServerBin,	/* output binary, freed @10 */
			&nonceServerBinSize,
			nonceServerString);	/* input string */
    }
    /* convert the pcrData to the TPM_PCR_INFO_SHORT */
    TPM_PCR_INFO_SHORT pcrData;
    if (rc == 0) {
	uint8_t *buffer = pcrDataBin;
	uint32_t size = pcrDataBinSize;
	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshal(&pcrData, &buffer, &size);
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
	rc = TSS_Structure_Marshal(&q1Buffer,	/* freed @11 */
				   &q1Written,
				   &q1,
				   (MarshalFunction_t)TSS_TPM_QUOTE_INFO2_Marshal);
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
	if (vverbose) Array_Print(NULL, "processQuote12: quote digest", TRUE,
				  (uint8_t *)&q1Digest.digest, SHA1_DIGEST_SIZE);
	if (vverbose) Array_Print(NULL, "processQuote12: signature", TRUE,
				  signatureBin, signatureBinSize);
    }
    X509 		*x509 = NULL;		/* public key */
    /* convert the quote verification PEM certificate to X509 */
    if (rc == 0) {
	rc = convertPemMemToX509(&x509,			/* freed @12 */
				 akCertificatePem);
    }
    RSA  		*rsaPkey = NULL;
    /* extract the RSA key token from the X509 certificate */
    if (rc == 0) {
	rc = convertX509ToRsa(&rsaPkey,			/* freed @13 */
			      x509);
    }
    /* verify the quote signature against the hash of the TPM_QUOTE_INFO */
    if (rc == 0) {
	irc = RSA_verify(NID_sha1,
			 (uint8_t *)&q1Digest.digest, SHA1_DIGEST_SIZE,
			 signatureBin, signatureBinSize, 
			 rsaPkey);
	if (irc != 1) {		/* quote signature did not verify */
	    rc = ACE_QUOTE_SIGNATURE;	/* skip reset of the tests */
	    quoteVerified = FALSE;	/* remains false */
	    printf("ERROR: processQuote12: Signature verification failed\n");
	}
	else {
	    quoteVerified = TRUE;	/* tentative */
	    if (verbose) printf("INFO: processQuote12: quote signature verified\n");
	}
    }
    /* validate the PCR values from the client against their hash in the TPM_PCR_INFO_SHORT
       pcrData */
    TPM_PCR_SELECTION 	pcrSelection;
    TPMT_HA		digestAtRelease;
    if (rc == 0) {
	uint32_t valueSize;
	makePcrSelect12(&valueSize, &pcrSelection);	/* this is the server (trusted) value */
	uint16_t sizeOfSelectNbo = htons(pcrSelection.sizeOfSelect);
	uint32_t valueSizeNbo = htonl(valueSize);
	digestAtRelease.hashAlg = TPM_ALG_SHA1;
	/* construct and hash the TPM_PCR_COMPOSITE */
	rc = TSS_Hash_Generate(&digestAtRelease,
			       sizeof(uint16_t), &sizeOfSelectNbo,
			       pcrSelection.sizeOfSelect, pcrSelection.pcrSelect,
			       sizeof(uint32_t), &valueSizeNbo,
			       
			       ((pcrSelection.pcrSelect[0] >> 0) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 0],
			       ((pcrSelection.pcrSelect[0] >> 1) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 1],
			       ((pcrSelection.pcrSelect[0] >> 2) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 2],
			       ((pcrSelection.pcrSelect[0] >> 3) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 3],
			       ((pcrSelection.pcrSelect[0] >> 4) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 4],
			       ((pcrSelection.pcrSelect[0] >> 5) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 5],
			       ((pcrSelection.pcrSelect[0] >> 6) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 6],
			       ((pcrSelection.pcrSelect[0] >> 7) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 7],
			       ((pcrSelection.pcrSelect[1] >> 0) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 8],
			       ((pcrSelection.pcrSelect[1] >> 1) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[ 9],
			       ((pcrSelection.pcrSelect[1] >> 2) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[10],
			       ((pcrSelection.pcrSelect[1] >> 3) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[11],
			       ((pcrSelection.pcrSelect[1] >> 4) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[12],
			       ((pcrSelection.pcrSelect[1] >> 5) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[13],
			       ((pcrSelection.pcrSelect[1] >> 6) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[14],
			       ((pcrSelection.pcrSelect[1] >> 7) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[15],
			       ((pcrSelection.pcrSelect[2] >> 0) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[16],
			       ((pcrSelection.pcrSelect[2] >> 1) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[17],
			       ((pcrSelection.pcrSelect[2] >> 2) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[18],
			       ((pcrSelection.pcrSelect[2] >> 3) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[19],
			       ((pcrSelection.pcrSelect[2] >> 4) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[20],
			       ((pcrSelection.pcrSelect[2] >> 5) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[21],
			       ((pcrSelection.pcrSelect[2] >> 6) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[22],
			       ((pcrSelection.pcrSelect[2] >> 7) & 0x01) ? SHA1_DIGEST_SIZE : 0,
			       quotePcrsSha1Bin[23],
			       0, NULL);
    }
    /* validate against TPM_PCR_INFO_SHORT pcrData, which was already signature checked above */
    if (rc == 0) {
	int irc = memcmp((uint8_t *)pcrData.digestAtRelease,
			 (uint8_t *)&digestAtRelease.digest, SHA1_DIGEST_SIZE);
	if (irc != 0) {
	    printf("ERROR: processQuote12: quoted PCR digest does not match PCRs\n");
	    if (vverbose) Array_Print(NULL, "validatePcrs: Digest from quote", TRUE,
				      (uint8_t *)pcrData.digestAtRelease,
				      SHA1_DIGEST_SIZE);
	    if (vverbose) Array_Print(NULL, "validatePcrs: Digest from PCRs", TRUE,
				      (uint8_t *)&digestAtRelease.digest,
				      SHA1_DIGEST_SIZE);
	    rc = ACE_PCR_VALUE;	/* skip reset of the tests */
	    quoteVerified = FALSE;
	    printf("ERROR: processQuote12: PCR verification failed\n");
	}
	else {
	    quoteVerified = TRUE;
	    if (verbose) printf("INFO: processQuote12: PCRs match quote data\n");
	}
    }
    /*
      Processing once the quote is verified completely, (rc is still 0)
    */
    /* determine whether BIOS PCRs match the previous quote. If no previous quote, PCRs do not
       match.  */
    if (rc == 0) {
	if (verbose) printf("INFO: processQuote12: Check previous BIOS PCRs\n");  
	rc = checkBiosPCRsMatch12(&previousBiosPcrs,
				  &biosPcrsMatch,
				  mysql,
				  quotePcrsSha1String,
				  hostname);
	if (biosPcrsMatch) {
	    biosevents = -1;		/* BIOS event log not needed */
	}
	else {
	    biosevents = 0;		/* BIOS event is always full, not incremental */
	}
    }
    /* if the BIOS PCRs did not change, determine if the IMA PCR changed */
    if ((rc == 0) && biosPcrsMatch) {
	if (verbose) printf("INFO: processQuote12: Check previous IMA PCRs\n");  
	rc = checkImaPCRsMatch12(&imaPcrsMatch,
				 quotePcrsSha1String,
				 imapcr);
	if (imaPcrsMatch) {
	    imaevents = -1;
	}
    }
    /* get PCRs from the first attestation, this is the white list */
    const char *firstPcrsSha1String[IMPLEMENTATION_PCR];
    if (rc == 0) {
	rc = SQ_GetFirstPcrs(firstPcrsSha1String,	/* SHA-1 */
			     NULL,			/* SHA-256 */
			     &machineResult,		/* freed @7 */
			     mysql,
			     hostname);
	/* no PCR white list */
	if ((firstPcrsSha1String[0] == NULL) && quoteVerified) {
	    /* store the first quote PCRs in the machines table as a white list */
	    storePcrWhiteList = TRUE;	/* flag, store it in machines DB */
	}
    }
    /* if there were first values, use as white list, check if any changed */
    if ((rc == 0) && !storePcrWhiteList && quoteVerified) {
	if (vverbose) printf("processQuote12: validate quote BIOS PCRs vs. white list\n");  
	for (pcrNum = 0 ; (pcrNum < 8) && !pcrinvalid ; pcrNum++) {
	    irc = strcmp(firstPcrsSha1String[pcrNum], quotePcrsSha1String[pcrNum]);
	    if (irc != 0) {
		if (verbose) printf("INFO: processQuote12: PCR %02u invalid\n", pcrNum);  
		if (verbose) printf("INFO: processQuote12: current PCR %s\n",
				    quotePcrsSha1String[pcrNum]);
		if (verbose) printf("INFO: processQuote12: valid   PCR %s\n",
				    firstPcrsSha1String[pcrNum]);
		pcrinvalid = TRUE;
		break;
	    }
	}
	if (!pcrinvalid) {
	    if (verbose) printf("INFO: processQuote12: quote PCRs match white list\n");
	}
	else {
	    if (verbose) printf("INFO: processQuote12: quote PCRs do not match white list\n");
	}
    }
    /*
      store the results in DB
    */
    char query[QUERY_LENGTH_MAX];
    /*
      machines table
    */
    /* first time, write PCR white list, if quote did not verify, don't store counterfeit PCR
       values */
    if (verbose && (rc == 0) && storePcrWhiteList)
	printf("INFO: processQuote12: store PCR white list\n");
    for (pcrNum = 0 ;
	 (rc == 0) && storePcrWhiteList && (machineId != NULL) && (pcrNum < IMPLEMENTATION_PCR) ;
	 pcrNum++) {
	
	sprintf(query,
		"update machines set pcr%02usha1 = '%s' where id = '%s'",
		pcrNum, quotePcrsSha1String[pcrNum], machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* first time, or new boot cycle, reset imaevents (next event to be processed) */
    if ((rc == 0) && (machineId != NULL)) {
	int irc = 0;
	if (!storePcrWhiteList) {
	    irc = strcmp(boottime, clientBoottime);	/* is this a new client boot cycle */
	}
	if (storePcrWhiteList || (irc != 0)) {
	    if (verbose) printf("INFO: processQuote12: new boot cycle, reset imaevents\n");
	    imaevents = 0;
	    /* reset the imaevents counter, indicates a reboot to the next step, hard code to
	       SHA-256 */
	    sprintf(query,
		    "update machines set imaevents = '%u', imapcr = '%s' where id = '%s'",
		    imaevents, "0000000000000000000000000000000000000000",
		    machineId);
	    rc = SQ_Query(NULL,
			  mysql, query);
	}
    }
    /* boottime to machines */
    if ((rc == 0) && (machineId != NULL)) {
	if (verbose) printf("INFO: processQuote12: store boottime %s\n", clientBoottime);
	sprintf(query,
		"update machines set boottime = '%s' where id = '%s'",
		clientBoottime, machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /*
      attestlog table
    */
    /* PCRs change from previous value, only if quoteverified, rc is 0, and there were previous
       PCRs */
    if ((rc == 0) && previousBiosPcrs && (attestLogId != NULL)) {
	sprintf(query,
		"update attestlog set pcrschanged = '%u' where id = '%s'",
		!biosPcrsMatch, attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* write quote PCRs, only if quoteverified, rc is 0 */
    for (pcrNum = 0 ;
	 (rc == 0) && (attestLogId != NULL) && (pcrNum < IMPLEMENTATION_PCR) ;
	 pcrNum++) {
	
	sprintf(query,
		"update attestlog set pcr%02usha1 = '%s' where id = '%s'",
		pcrNum, quotePcrsSha1String[pcrNum], attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* PCRs invalid vs white list (only if there was a white list) */
    if ((rc == 0) && !storePcrWhiteList && (attestLogId != NULL)) {
	sprintf(query,
		"update attestlog set pcrinvalid = '%u' where id = '%s'",
		pcrinvalid, attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* quoteVerified */
    uint32_t rc2;
    if (attestLogId != NULL) {
	sprintf(query,
		"update attestlog set quoteverified = '%u' where id = '%s'",
		quoteVerified, attestLogId);
	rc2 = SQ_Query(NULL,
		       mysql, query);
	if (rc == 0) {
	    rc = rc2;
	}
    }
    /* boottime to attestlog */
    /* add raw quoted data to attestlog */
    if (attestLogId != NULL) {
	sprintf(query,
		"update attestlog set boottime = '%s', quote = '%s' where id = '%s'",
		clientBoottime, cmdBuffer, attestLogId);
	rc2 = SQ_Query(NULL,
		       mysql, query);
	if (rc == 0) {
	    rc = rc2;
	}
    }
    /*
      create the quote return json
    */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @14 */
    if (rc1 == 0) {
	char eventsString[16];
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("quote"));
	}
	if (rc == 0) {
	    sprintf(eventsString, "%d", biosevents);
	    json_object_object_add(response, "biosentry",
				   json_object_new_string(eventsString));
	}
	if (rc == 0) {
	    sprintf(eventsString, "%d", imaevents);
	    json_object_object_add(response, "imaentry",
				   json_object_new_string(eventsString));
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
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	free(quotePcrsSha1Bin[pcrNum]);	/* @1 */
    }
    free(pcrDataBin);			/* @2 */ 
    free(versionInfoBin);		/* @3 */ 
    free(signatureBin);			/* @4 */ 
    SQ_Close(mysql);			/* @5 */
    free(machineId);			/* @6 */
    SQ_FreeResult(machineResult);	/* @7 */
    free(attestLogId);			/* @8 */
    SQ_FreeResult(attestLogResult);	/* @9 */
    free(nonceServerBin);		/* @10 */
    free(q1Buffer);			/* @11 */
    if (x509 != NULL) {
	X509_free(x509);		/* @12 */
    }
    if (rsaPkey != NULL) {
	RSA_free(rsaPkey);		/* @13 */
    }
    return rc;
}

#endif /* TPM_TPM12 */

/* makePcrSelect() creates the PCR select structure, PCR0-7 SHA256 for BIOS and PCR10 SHA-256 for
   IMA. */

/* NOTE This has to be kept in sync with the tests for PCRs changed */

static void makePcrSelect(TPML_PCR_SELECTION *pcrSelection)
{
    pcrSelection->count = 2;		/* two banks */
    /* TPMS_PCR_SELECTION */
    pcrSelection->pcrSelections[0].hash = TPM_ALG_SHA256;
    pcrSelection->pcrSelections[0].sizeofSelect = 3;
    pcrSelection->pcrSelections[0].pcrSelect[0] = 0xff;	/* PCR0-7 */
    pcrSelection->pcrSelections[0].pcrSelect[1] = 0x04;	/* PCR 10, IMA_PCR */
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

static void makePcrSelect12(uint32_t *valueSize,	/* size of PCR array */
			    TPM_PCR_SELECTION *pcrSelection)
{
    pcrSelection->sizeOfSelect = 3;
    pcrSelection->pcrSelect[0] = 0xff;	/* PCR0-7 */
    pcrSelection->pcrSelect[1] = 0x04;	/* PCR 10, IMA_PCR */
    pcrSelection->pcrSelect[2] = 0x00;
    *valueSize = (9 * SHA1_DIGEST_SIZE);	/* 9 PCRs selected */
    return;
}

#endif

/* pcrStringToBin() converts the PCRs as hexascii strings to binary.

   The strings typically come frome either the database or json.
*/

static uint32_t pcrStringToBin(unsigned char **pcrsSha1Bin,	/* freed by the caller */
			       size_t *pcrsSha1BinSize,
			       unsigned char **pcrsSha256Bin, 	/* freed by the caller */
			       size_t *pcrsSha256BinSize,
			       const char *pcrsSha1String[],
			       const char *pcrsSha256String[])
{
    uint32_t  		rc = 0;
    /* NULL the pointers for the free */
    uint32_t pcrNum;
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	pcrsSha1Bin[pcrNum] = NULL;
	pcrsSha256Bin[pcrNum] = NULL;
    }
    /* get all PCRs from the strings */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	/* text to binary */
	if (rc == 0) {
	    rc = Array_Scan(&pcrsSha1Bin[pcrNum],	/* output binary, freed by the caller */
			    &pcrsSha1BinSize[pcrNum],
			    pcrsSha1String[pcrNum]);	/* input string */
	
	}
	if (rc == 0) {
	    rc = Array_Scan(&pcrsSha256Bin[pcrNum],	/* output binary, freed by the caller */
			    &pcrsSha256BinSize[pcrNum],
			    pcrsSha256String[pcrNum]);	/* input string */
	
	}
	if (pcrsSha1BinSize[pcrNum] != SHA1_DIGEST_SIZE) {
	    printf("ERROR: pcrStringToBin: PCR %u size %lu not SHA-1\n",
		   pcrNum, (unsigned long)pcrsSha1BinSize[pcrNum]);  
	    rc = ACE_PCR_LENGTH;
	}
	if (pcrsSha256BinSize[pcrNum] != SHA256_DIGEST_SIZE) {
	    printf("ERROR: pcrStringToBin: client PCR %u size %lu not SHA-256\n",
		   pcrNum, (unsigned long)pcrsSha256BinSize[pcrNum]);  
	    rc = ACE_PCR_LENGTH;
	}
    }
    return rc;
}

/* makePcrStream() concatenates the selected PCRs into a stream. pcrBinStream must be large enough
   to hold the stream.

   This is used to create the pcrDigest for a quote or policy.
*/

static uint32_t makePcrStream(unsigned char 	*pcrBinStream,
			      size_t 		*pcrBinStreamSize,
			      unsigned char 	**pcrsSha1Bin,
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
		if (vverbose) printf("makePcrStream: using bank %u PCR %u\n", bank, pcrNum);
		if (halg == TPM_ALG_SHA1) {
#if 0
		    if (vverbose) Array_Print(NULL, "makePcrStream: PCR", TRUE,
					      pcrsSha1Bin[pcrNum], SHA1_DIGEST_SIZE);
#endif
		    memcpy(pcrBinStream + *pcrBinStreamSize,
			   pcrsSha1Bin[pcrNum], SHA1_DIGEST_SIZE);
		    *pcrBinStreamSize += SHA1_DIGEST_SIZE;
		}
		else if (halg == TPM_ALG_SHA256) {
#if 0
		    if (vverbose) Array_Print(NULL, "makePcrStream: PCR", TRUE,
					      pcrsSha256Bin[pcrNum], SHA256_DIGEST_SIZE);
#endif
		    memcpy(pcrBinStream + *pcrBinStreamSize,
			   pcrsSha256Bin[pcrNum], SHA256_DIGEST_SIZE);
		    *pcrBinStreamSize += SHA256_DIGEST_SIZE;
		}
		else {
		    printf("ERROR: makePcrStream: Hash algorithm %04x not supported\n", halg);
		    rc = ASE_BAD_ALG;
		}
	    }
	}
    }
    return rc;
}

/* validatePcrs() validates the received PCRs against the PCR digest in quoted.  Also validates that
   the PCR selection from the client is the same as the requested selection from the server.

*/

static uint32_t validatePcrs(const char *pcrsSha1String[],
			     const char *pcrsSha256String[],
			     TPMS_ATTEST *tpmsAttest)
{
    uint32_t  		rc = 0;

    /* read the PCRs from the command json, convert to binary */
    unsigned char *pcrsSha1Bin[IMPLEMENTATION_PCR];
    size_t pcrsSha1BinSize[IMPLEMENTATION_PCR];
    unsigned char *pcrsSha256Bin[IMPLEMENTATION_PCR];
    size_t pcrsSha256BinSize[IMPLEMENTATION_PCR];
    uint32_t pcrNum;
    /* NULL the pointers for the free */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	pcrsSha1Bin[pcrNum] = NULL;
	pcrsSha256Bin[pcrNum] = NULL;
    }
    if (rc == 0) {
	rc = pcrStringToBin(pcrsSha1Bin,	/* freed @1 */
			    pcrsSha1BinSize,
			    pcrsSha256Bin, 	/* freed @2 */
			    pcrsSha256BinSize,
			    pcrsSha1String,
			    pcrsSha256String);
    }
    TPML_PCR_SELECTION serverPcrSelection;
    TPML_PCR_SELECTION *clientPcrSelection;
    /* compare pcrSelect to requested value */
    if (rc == 0) {
	makePcrSelect(&serverPcrSelection);
	clientPcrSelection = &tpmsAttest->attested.quote.pcrSelect;
    }
    if (rc == 0) {
	/* check the banks selected */
	if (clientPcrSelection->count != serverPcrSelection.count) {
	    printf("ERROR: validatePcrs: Client PCR banks %u does not match server %u\n",
		   clientPcrSelection->count, serverPcrSelection.count);
	    rc = ACE_PCR_BANK;
	}
    }
    uint32_t bank;
    for (bank = 0 ; (rc == 0) && (bank < clientPcrSelection->count) ; bank++) {
	/* check the algorithms for the banks */
	if (clientPcrSelection->pcrSelections[bank].hash !=
	    serverPcrSelection.pcrSelections[bank].hash) {
	    printf("ERROR: validatePcrs: "
		   "Client PCR bank %u hashalg %04x does not match server %04x\n", bank,
		   clientPcrSelection->pcrSelections[bank].hash,
		   serverPcrSelection.pcrSelections[bank].hash);
	    rc = ACE_PCR_BANK;
	}
	/* check sizeofselect */
	if (clientPcrSelection->pcrSelections[bank].sizeofSelect !=
	    serverPcrSelection.pcrSelections[bank].sizeofSelect) {
	    printf("ERROR: validatePcrs: Client PCR sizeofSelect %u does not match server %u\n",
		   clientPcrSelection->pcrSelections[bank].sizeofSelect,
		   serverPcrSelection.pcrSelections[bank].sizeofSelect);
	    rc = ACE_PCR_SELECT;
	}
	uint8_t byte;
	/* check that the client PCR selection bitmask is what the server requested */
	for (byte = 0 ; byte < clientPcrSelection->pcrSelections[bank].sizeofSelect ; byte++) {
	    if (clientPcrSelection->pcrSelections[bank].pcrSelect[byte] !=
		serverPcrSelection.pcrSelections[bank].pcrSelect[byte]) {
		printf("ERROR: validatePcrs: "
		       "Client byte %u select %02x does not match server %02x\n", byte, 
		       clientPcrSelection->pcrSelections[bank].pcrSelect[byte],
		       serverPcrSelection.pcrSelections[bank].pcrSelect[byte]);  
		rc = ACE_PCR_SELECT;
	    }
	}
    }
    /* concatenate the PCRs */
    unsigned char pcrBinStream[HASH_COUNT * IMPLEMENTATION_PCR * MAX_DIGEST_SIZE];
    size_t pcrBinStreamSize = 0;
    if (rc == 0) {
	rc = makePcrStream(pcrBinStream,
			   &pcrBinStreamSize,
			   pcrsSha1Bin,
			   pcrsSha256Bin,
			   clientPcrSelection);
    }
    /* construct the client pcrDigest */
    TPMT_HA digest;
    if (rc == 0) {
#if 0
	if (vverbose) Array_Print(NULL, "validatePcrs: PCR stream", TRUE,
				  pcrBinStream, pcrBinStreamSize);
#endif
	digest.hashAlg = TPM_ALG_SHA256;	/* algorithm of signing key */
	rc = TSS_Hash_Generate(&digest,
			       pcrBinStreamSize, pcrBinStream,
			       0, NULL);
    }
    /* validate against pcrDigest in quoted */
    if (rc == 0) {
	if (tpmsAttest->attested.quote.pcrDigest.t.size != SHA256_DIGEST_SIZE) {
	    printf("ERROR: validatePcrs: quoted PCR digest size %u not supported\n",
		   tpmsAttest->attested.quote.pcrDigest.t.size);  
	    rc = ACE_DIGEST_LENGTH;
	}
    }
    if (rc == 0) {
	int irc = memcmp(tpmsAttest->attested.quote.pcrDigest.t.buffer,
			 (uint8_t *)&digest.digest, SHA256_DIGEST_SIZE);
	if (irc != 0) {
	    printf("ERROR: validatePcrs: quoted PCR digest does not match PCRs\n");
	    if (vverbose) Array_Print(NULL, "validatePcrs: Digest from quote", TRUE,
				      tpmsAttest->attested.quote.pcrDigest.t.buffer,
				      SHA256_DIGEST_SIZE);
	    if (vverbose) Array_Print(NULL, "validatePcrs: Digest from PCRs", TRUE,
				      (uint8_t *)&digest.digest,
				      SHA256_DIGEST_SIZE);
	    rc = ACE_DIGEST_VALUE;
	}
    }
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	free(pcrsSha1Bin[pcrNum]);		/* @1 */
    }
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	free(pcrsSha256Bin[pcrNum]);		/* @2 */
    }
    return rc;
}

/* checkBiosPCRsMatch() determines whether PCRs match the previous valid quote.

   If there was a previous successful quote, previousBiosPcrs is TRUE.  If the current BIOS PCRs
   match the previous value, biosPcrsMatch is TRUE, else FALSE.

   If there was no previous successful quote, previousBiosPcrs is FALSE and biosPcrsMatch is FALSE.
*/

static uint32_t checkBiosPCRsMatch(unsigned int *previousBiosPcrs,
				   unsigned int *biosPcrsMatch,
				   MYSQL	*mysql,
				   const char	*quotePcrsSha256String[],
				   const char 	*hostname)
{
    uint32_t  		rc = 0;
    MYSQL_RES 		*previousAttestLogResult = NULL;
    const char		*previousPcrsSha1String[IMPLEMENTATION_PCR];
    const char		*previousPcrsSha256String[IMPLEMENTATION_PCR];

    *biosPcrsMatch = FALSE;		/* unless match detected */
    /* get the previous PCRs */
    if (rc == 0) {
	rc = SQ_GetPreviousPcrs(previousPcrsSha1String,
				previousPcrsSha256String,
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
    else if (previousPcrsSha256String[0] == NULL) {
	if (verbose)
	    printf("INFO: checkBiosPCRsMatch: No previous PCRs, previous attestations failed\n");
	*previousBiosPcrs = FALSE;
	rc = 0;
    }
    /* have previous PCRs to compare */
    else {
	*previousBiosPcrs = TRUE;
	*biosPcrsMatch = TRUE;
	/* check the BIOS PCR, SHA-256 PCR 0-7 */
	/* FIXME it would be better to key this off PCR select than hard code PCR 0-7 */
	uint32_t pcrNum;
	for (pcrNum = 0 ; *biosPcrsMatch && (pcrNum < 8) ; pcrNum++) {

	    int irc = strcmp(previousPcrsSha256String[pcrNum], quotePcrsSha256String[pcrNum]);
	    /* PCR changed */
	    if (irc != 0) {
		if (verbose) printf("INFO: checkBiosPCRsMatch: PCR %u changed\n", pcrNum);
		*biosPcrsMatch = FALSE;

	    }
	}
	if (*biosPcrsMatch) {
	    if (verbose) printf("INFO: checkBiosPCRsMatch: PCRs did not change\n");
	}
    }
    SQ_FreeResult(previousAttestLogResult);		/* @1 */
    previousAttestLogResult = NULL;
    return rc;
}

#ifdef TPM_TPM12

/* checkBiosPCRsMatch12() determines whether PCRs match the previous valid quote.

   If there was a previous successful quote, previousBiosPcrs is TRUE.  If the current BIOS PCRs
   match the previous value, biosPcrsMatch is TRUE, else FALSE.

   If there was no previous successful quote, previousBiosPcrs is FALSE anf biosPcrsMatch is FALSE.

*/

static uint32_t checkBiosPCRsMatch12(unsigned int 	*previousBiosPcrs,
				     unsigned int 	*biosPcrsMatch,
				     MYSQL		*mysql,
				     const char		*quotePcrsSha1String[],
				     const char 	*hostname)
{
    uint32_t  		rc = 0;
    MYSQL_RES 		*previousAttestLogResult = NULL;
    const char		*previousPcrsSha1String[IMPLEMENTATION_PCR];

    *biosPcrsMatch = FALSE;		/* unless match detected */
    /* get the previous PCRs */
    if (rc == 0) {
	rc = SQ_GetPreviousPcrs(previousPcrsSha1String,
				NULL,				/* no SHA-256 bank */
				&previousAttestLogResult,	/* freed @1 */
				mysql,
				hostname,
				NULL);				/* boottime not used */
    }
    /* if there was no previous successful attestation for this host */
    if (rc != 0) {			/* first time for this host */
	if (verbose) printf("INFO: checkBiosPCRsMatch12: No previous PCRs, first attestation\n");
	*previousBiosPcrs = FALSE;
	rc = 0;
    }
    /* NULL means that previous attestations failed */
    else if (previousPcrsSha1String[0] == NULL) {
	if (verbose)
	    printf("INFO: checkBiosPCRsMatch12: No previous PCRs, previous attestations failed\n");
	*previousBiosPcrs = FALSE;
	rc = 0;
    }
    /* have previous PCRs to compare */
    else {
	*previousBiosPcrs = TRUE;
	*biosPcrsMatch = TRUE;
	/* check the BIOS PCR, SHA-1 PCR 0-7 */
	/* FIXME it would be better to key this off PCR select than hard code PCR 0-7 */
	uint32_t pcrNum;
	for (pcrNum = 0 ; *biosPcrsMatch && (pcrNum < 8) ; pcrNum++) {

	    int irc = strcmp(previousPcrsSha1String[pcrNum], quotePcrsSha1String[pcrNum]);
	    /* PCR changed */
	    if (irc != 0) {
		if (verbose) printf("INFO: checkBiosPCRsMatch12: PCR %u changed\n", pcrNum);
		*biosPcrsMatch = FALSE;

	    }
	}
	if (*biosPcrsMatch) {
	    if (verbose) printf("INFO: checkBiosPCRsMatch12: PCRs did not change\n");
	}
    }
    SQ_FreeResult(previousAttestLogResult);		/* @1 */
    previousAttestLogResult = NULL;
    return rc;
}

#endif

/* checkImaPCRsMatch() compares the IMA PCR value from the quote with that of the last successful
   IMA event log verification

*/

static uint32_t checkImaPCRsMatch(unsigned int 	*imaPcrsMatch,
				  const char	*quotePcrsSha256String[],
				  const char 	*imapcr)
{
    uint32_t  		rc = 0;

    /* sanity check.  imapcr should be initialized when the quote verifies.  NULL is a server
       error */
    if (rc == 0) {
	if (imapcr == NULL) {
	    printf("ERROR: checkImaPCRsMatch: server error, imapcr is NULL\n");
	    rc = ASE_NULL_VALUE;
	}
    }
    if (rc == 0) {
	if (vverbose)
	    printf("checkImaPCRsMatch: last IMA PCR %s\n", imapcr);
	if (vverbose)
	    printf("checkImaPCRsMatch: current quote PCR %s\n", quotePcrsSha256String[IMA_PCR]);
	int irc = strcmp(imapcr, quotePcrsSha256String[IMA_PCR]);
	/* IMA PCR did not change */
	if (irc == 0) {
	    if (verbose) printf("INFO: checkImaPCRsMatch: IMA PCR did not change\n");
	    *imaPcrsMatch = TRUE;
	}
	/* else if IMA PCR changed, use imaevents stored from the previous IMA processing
	   for an incremental update */
	else {
	    if (verbose) printf("INFO: checkImaPCRsMatch: IMA PCR changed\n");
	    *imaPcrsMatch = FALSE;
	}
    }
    return rc;
}

#if TPM_TPM12

/* checkImaPCRsMatch12() compares the IMA PCR value from the quote with that of the last successful
   IMA event log verification

*/

static uint32_t checkImaPCRsMatch12(unsigned int 	*imaPcrsMatch,
				  const char		*quotePcrsSha1String[],
				  const char 		*imapcr)
{
    uint32_t  		rc = 0;

    /* sanity check.  imapcr should be initialized when the quote verifies.  NULL is a server
       error */
    if (rc == 0) {
	if (imapcr == NULL) {
	    printf("ERROR: checkImaPCRsMatch12: server error, imapcr is NULL\n");
	    rc = ASE_NULL_VALUE;
	}
    }
    if (rc == 0) {
	if (vverbose)
	    printf("checkImaPCRsMatch12: last IMA PCR %s\n", imapcr);
	if (vverbose)
	    printf("checkImaPCRsMatch12: current quote PCR %s\n", quotePcrsSha1String[IMA_PCR]);
	int irc = strcmp(imapcr, quotePcrsSha1String[IMA_PCR]);
	/* IMA PCR did not change */
	if (irc == 0) {
	    if (verbose) printf("INFO12: checkImaPCRsMatch: IMA PCR did not change\n");
	    *imaPcrsMatch = TRUE;
	}
	/* else if IMA PCR changed, use imaevents stored from the previous IMA processing
	   for an incremental update */
	else {
	    if (verbose) printf("INFO12: checkImaPCRsMatch: IMA PCR changed\n");
	    *imaPcrsMatch = FALSE;
	}
    }
    return rc;
}

#endif

/* processBiosEntry() processes an BIOS event log entry list.

   In the first pass, it validates the event log against the PCRs previously validated by the quote
   and stored in the DB.

   In the second pass, the entry event is processed.

   The client command is:

   {
   "command":"biosentry",
   "hostname":"cainl.watson.ibm.com",
   "nonce":"1298d83cdd8c50adb58648d051b1a596b66698758b8d0605013329d0b45ded0c",
   "eventn":"hexascii"
   }

   eventn - a list starting with event 1 (the informational event is not sent now)

   ~~

   It updates the attestlog with:

   logverified - event log verifies against PCRs
   logentries - number of entries in event log

   ~~

   The client response is:
   
   {
   "response":"biosentry"
   "imaentry":"0"
   }

   where imaentry indicates the IMA processing

   0 full log starting with entry 0
   >0 incremental log starting at that number
   -1 no log
*/

static uint32_t processBiosEntry(unsigned char **rspBuffer,	/* freed by caller */
				 uint32_t *rspLength,
				 json_object *cmdJson)
{
    uint32_t  		rc = 0;		/* server error, should never occur, aborts processing */
    int			tpm20 = TRUE;
    unsigned int 	pcrNum;
    int 		biosPcrsVerified = 0;	/* default to false in case previous step failed */
    int 		eventNum = 0;		/* the current BIOS event being processed */

    /* from client */
    const char 		*hostname = NULL;

    /* from database */
    MYSQL 		*mysql = NULL;
    const char 		*clientBootTime = NULL;
    const char 		*timestamp = NULL;
    char 		*attestLogId = NULL;		/* row being updated */

    if (vverbose) printf("INFO: processBiosEntry: Entry\n");
    /* get the command, nonce for TPM 2.0 and nonce12 for TPM 1.2 */
    const char *commandString;
    if (rc == 0) {
	rc = JS_ObjectGetString(&commandString, "command", cmdJson);
    }
    if (rc == 0) {
	if (strcmp(commandString, "biosentry12") == 0) {	/* TPM 1.2 */
	    tpm20 = FALSE;
	}
    }
#ifndef TPM_TPM12
    if (rc == 0) {
	if (!tpm20) {
	    printf("ERROR: processBiosEntry: Client TPM 1.2 not supported\n");
	    rc = ACE_TPM12_UNSUPPORTED;
	}
    }
#endif
    /* get the client machine name */
    if (rc == 0) {
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* get the client nonce command */
    const char *clientNonceString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&clientNonceString, "nonce", cmdJson);
    }
    /* connect to the db */
    if (rc == 0) {
	rc = SQ_Connect(&mysql);	/* closed @1 */	
    }
    /* get the DB information for this machine, verify that machine is enrolled */
    MYSQL_RES  	*machineResult = NULL;
    char 	*machineId = NULL;	/* row being updated */
    const char 	*boottime;		
    int 	imaevents;
    const char *imapcr;
    if (rc == 0) {
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @2 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				NULL,			/* akcertificatepem */
				NULL, 			/* akcertificatetext */
				NULL, 			/* enrolled */
				&boottime,		/* boottime */
				&imaevents,		/* imaevents */
				&imapcr,		/* imapcr */
				&machineResult,		/* freed @3 */
				mysql,
				hostname);
	if (rc != 0) {
	    printf("ERROR: processBiosEntry: row for hostname %s does not exist in machine table\n",
		   hostname);
	}
    }
    /* get the attestlog row being updated.  If the row does not exist, fatal client error */
    MYSQL_RES  *attestLogResult = NULL;
    const char *serverNonceString = NULL;
    const char *logVerifiedString = NULL;
    const char *quoteVerifiedString = NULL;
    if (rc == 0) {
	rc = SQ_GetAttestLogEntry(&attestLogId,  	/* freed @4 */
				  &clientBootTime,	/* boottime */
				  &timestamp,		/* timestamp */
				  &serverNonceString,	/* nonce */
				  NULL,			/* pcrselect */
				  &quoteVerifiedString,	/* quoteverified */
				  &logVerifiedString,	/* logverified */
				  &attestLogResult,	/* freed @5 */
				  mysql,
				  hostname);
	/* this is a client error, indicating a bad hostname, or a hostname for the first time and
	   no nonce was requested. */
	if (rc != 0) {
	    printf("ERROR: processBiosEntry: "
		   "row for hostname %s does not exist in server database\n",
		   hostname);  
	    rc = ACE_NONCE_MISSING;
	}
	/* The DB logverified is used as state.  When the nonce is created, it is null, indicating
	   that the nonce has not been used to check an event log.  After BIOS entries have been
	   used, logverified is set true or false, indicating that the nonce has been used. */
	else if (logVerifiedString != NULL) {
	    printf("ERROR: processBiosEntry: nonce for hostname %s already used for events\n",
		   hostname);  
	    rc = ACE_NONCE_USED;
	}
	/* The DB quoteverified is used as state.  When the nonce is created, it is null, indicating
	   that the nonce has not been used to verify a quote.  At that time, an event log should
	   not be accepted yet.  After the quote, quoteverified is set true or false, indicating
	   that the quote has been verified. */    
	else if (quoteVerifiedString == NULL) {
	    printf("ERROR: processBiosEntry: nonce for hostname %s has not validated a quote\n",
		   hostname);  
	    rc = ACE_QUOTE_MISSING;
	}
	/* The server uses the nonce as a sort of one time cookie.  The client echoes the quote
	   nonce with the event log and the server checks for a match.  This prevents a rogue client
	   from masquerading as a client and causing mischief by sending an incorrect event log.  It
	   assumes that the nonce is a random value that cannot be guessed by the rogue.  */
	else if (strcmp(clientNonceString, serverNonceString) != 0) {
	    printf("ERROR: processBiosEntry: nonce for hostname %s from client does not match\n",
		   hostname);  
	    rc = ACE_NONCE_VALUE;
	}
    }
    /* Get the current BIOS PCR values for the machine name from the attestlog database.  It was
       received with the quote.
    */
    MYSQL_RES  *attestLogPcrResult = NULL;
    const char *quotePcrsSha1String[IMPLEMENTATION_PCR];   /* from quote, from database */
    const char *quotePcrsSha256String[IMPLEMENTATION_PCR]; /* from quote, from database */
    if (rc == 0) {
	rc = SQ_GetAttestLogPCRs(NULL,	
				 quotePcrsSha1String,
				 quotePcrsSha256String,
				 &attestLogPcrResult,	/* freed @6 */
				 mysql,
				 hostname);
    }
    /* convert current quote PCRs to binary array for extend and compare */
    size_t 		quotePcrsBinLength[IMPLEMENTATION_PCR];
    uint8_t 		*quotePcrsBin[IMPLEMENTATION_PCR];
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	quotePcrsBin[pcrNum] = NULL;			/* for free, in case of error */
    }
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	if (tpm20) {						/* TPM 2.0 SHA-256 */
	    if (quotePcrsSha256String[pcrNum] != NULL) {
		rc = Array_Scan(&quotePcrsBin[pcrNum],		/* freed @7 */
				&quotePcrsBinLength[pcrNum],
				quotePcrsSha256String[pcrNum]);	/* BIOS uses SHA-256 bank */
	    }
	}
#ifdef TPM_TPM12	/* unsupported screened out earlier */
	else {							/* TPM 1.2 SHA-1 */
	    if (quotePcrsSha1String[pcrNum] != NULL) {
		rc = Array_Scan(&quotePcrsBin[pcrNum],		/* freed @7 */
				&quotePcrsBinLength[pcrNum],
				quotePcrsSha1String[pcrNum]);	/* BIOS uses SHA-1 bank */
	    }
	}
#endif
	if (rc != 0) {
	    printf("ERROR: processBiosEntry: "
		   "hostname %s does not have PCRs in server database\n",
		   hostname);
	    rc = ACE_PCR_MISSING;
	}
    }
    /* Check the BIOS event digest against BIOS PCR.  If this fails, the event list is
       invalid, and there is no point in validating the individual entries.

       If the BIOS PCR calculation verifies, the second pass below validates individual entries.
    */
    if (rc == 0) {
	if (verbose) printf("INFO: processBiosEntry: First pass, validating BIOS PCR\n");
    }
    if (rc == 0) {
	if (tpm20) {						/* TPM 2.0 SHA-256 */
	    rc = processBiosEntryPass1(&biosPcrsVerified,	/* bool, BIOS PCRs matched */
				       &eventNum,		/* last bios entry processed */
				       cmdJson,			/* client command */
				       quotePcrsBin); 		/* BIOS PCRs in quote */
	}
#ifdef TPM_TPM12	/* unsupported screened out earlier */
	else {
	    rc = processBiosEntry12Pass1(&biosPcrsVerified,	/* bool, BIOS PCRs matched */
					 &eventNum,		/* last bios entry processed */
					 cmdJson,		/* client command */
					 quotePcrsBin); 	/* BIOS PCRs in quote */
	}
#endif
    }
    /* store errors as long as the row exists for this hostname */
    char query[QUERY_LENGTH_MAX];
    if ((rc == 0) && (attestLogId != NULL)) {
	sprintf(query,
		"update attestlog set logverified = '%u', logentries = '%u' where id = '%s'",
		biosPcrsVerified, eventNum, attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* pass 2 currently just parses the log for display */
    if (biosPcrsVerified) {
	if (rc == 0) {
	    if (verbose) printf("INFO: processBiosEntry: Second pass, storing BIOS entries\n");
	    if (tpm20) {						/* TPM 2.0 SHA-256 */
		rc = processBiosEntryPass2(hostname,	/* for DB row */
					   timestamp,	/* for DB row */
					   cmdJson,	/* client command */
					   mysql);
	    }
#ifdef TPM_TPM12	/* unsupported screened out earlier */
	    else {
		rc = processBiosEntry12Pass2(hostname,	/* for DB row */
					     timestamp,	/* for DB row */
					     cmdJson,	/* client command */
					     mysql);
	    }
#endif
	}
	/*
	  check for IMA PCR change
	*/
	/* zero indicates reboot or first time, ask for entire IMA log */
	if (imaevents != 0) {	/* not reboot and not first time */
	    unsigned int imaPcrsMatch;
	    if (rc == 0) {
		/* check the current quote IMA PCR against the value stored at the last successful
		   IMA event log value.  This is usually the same as the previous quote value, but
		   it can be different if the IMA log verification failed. */
		if (tpm20) {						/* TPM 2.0 SHA-256 */
		    rc = checkImaPCRsMatch(&imaPcrsMatch,
					   quotePcrsSha256String,
					   imapcr);
		}							/* TPM 1.2 SHA-1 */
#ifdef TPM_TPM12	/* unsupported screened out earlier */
		else {
		    rc = checkImaPCRsMatch(&imaPcrsMatch,
					   quotePcrsSha1String,
					   imapcr);
		}
#endif
	    }
	    if (rc == 0) {
		if (imaPcrsMatch) {
		    imaevents = -1;	/* -1 indicates to the client that no IMA log is needed */
		}
	    }
	}
    }
    else {
	imaevents = -1;	/* if BIOS PCRs did not verify, don't ask for IMA log */
    }
    /* create the biosentry return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @1 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("biosentry"));
	}
	if (rc == 0) {
	    char imaEventsString[16];
	    sprintf(imaEventsString, "%d", imaevents);
	    json_object_object_add(response, "imaentry",
				   json_object_new_string(imaEventsString));
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
    SQ_Close(mysql);				/* @1 */
    free(machineId);				/* @2 */
    SQ_FreeResult(machineResult);		/* @3 */
    free(attestLogId);				/* @4 */
    SQ_FreeResult(attestLogResult);		/* @5 */
    SQ_FreeResult(attestLogPcrResult);		/* @6 */
    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	free(quotePcrsBin[pcrNum]);		/* @7 */
    }
    return rc;
}

/* processBiosEntryPass1() does the first pass through the client BIOS log entries.

   For each entry, it extends a PCR, starting at all zero after a reboot, and matches the
   result against the current BIOS PCRs from the quote.

   It exits when either:

   - an entry cannot be parsed
   - the calculated BIOS PCRs all match that of the quote
   - all client BIOS log entries have been processed
*/

static uint32_t processBiosEntryPass1(int *biosPcrVerified,	/* bool, BIOS PCRs matched */
				      int *eventNum,		/* last bios entry processed */
				      json_object *cmdJson,	/* client command, event log */
				      uint8_t *quotePcrsBin[])  /* BIOS PCRs in quote */
{
    uint32_t 		rc = 0;
    int			irc;
    unsigned int 	i;
    int			pcrMatch[TPM_BIOS_PCR];
    unsigned char 	zeroDigest[SHA256_DIGEST_SIZE];
    TPMT_HA		biosPcrs[1][TPM_BIOS_PCR];	/* one bank, just sha256 */

    if (vverbose) printf("INFO: processBiosEntryPass1: Entry\n");
    memset(zeroDigest, 0, SHA256_DIGEST_SIZE);
    *biosPcrVerified = 0;
    for (i = 0 ; i < TPM_BIOS_PCR ; i++) {
	/* BIOS PCRs start at zero */
	biosPcrs[0][i].hashAlg = TPM_ALG_SHA256;
	memset((uint8_t *)&biosPcrs[0][i].digest, 0, SHA256_DIGEST_SIZE);
	/* any quote PCRs that are still zero start off as matching, others start not matching */
	irc = memcmp(quotePcrsBin[i], zeroDigest, SHA256_DIGEST_SIZE);
	if (irc == 0) {
	    if (vverbose) printf("processBiosEntryPass1: BIOS PCR %u begins matched\n", i);
	    pcrMatch[i] = 1;
	}
	else {
	    pcrMatch[i] = 0;
	}
    }
    /* Continue until either

       1 - all BIOS PCR match
       2 - a PCR that was matching became not matching, SHA-256 says it can't ever match again
       3 - there are no more events.

       Note that BIOS PCRs can verify before all events are processed.  This occurs if more events
       occurred after the quote.  In that case, remaining events are discarded at the server and
       will be retried again during the next attestation.

       eventNum starts at 1 because event 0 is header information, EV_NO_ACTION
    */
    unsigned char *eventBin = NULL;
    for (*eventNum = 1 ; (rc == 0) && !(*biosPcrVerified) ; (*eventNum)++) {
	/* Check for all matches first, this handles the odd corner case of no BIOS measurements */
	if (rc == 0) { 
	    unsigned int count = 0;
	    for (i = 0 ; i < TPM_BIOS_PCR ; i++) {
		if (pcrMatch[i]) {
		    count++;
		}
	    }
	    if (count == TPM_BIOS_PCR) {
		if (vverbose) printf("processBiosEntryPass1: All BIOS PCR matched at event %u\n",
				     *eventNum - 1);
		*biosPcrVerified = 1;		/* matches, done */
		break;
	    }
	}
	/* get the next event */
	const char *eventString;
	size_t eventLength;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&eventString,
				 *eventNum,
				 cmdJson);
	    /* Case 3: If there is no next event, done walking measurement list.  This is not a json
	       error, because the server does not know in advance how many entries the client will
	       send.  However, since BIOS PCR did not match, there is an error to be processed
	       below.  */
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntryPass1: done, no event %u\n", *eventNum);  
		break;			/* exit the BIOS event loop */
	    } 
	}
	/* convert the event from a string to binary */
	if (rc == 0) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    eventString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntryPass1: error scanning event %u\n", *eventNum);
	    }
	}
	TCG_PCR_EVENT2 event2;	/* TPM 2.0 hash agile event log entry */
	/* unmarshal the event from binary to structure */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntryPass1: unmarshaling event %u\n", *eventNum);
	    unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
	    uint32_t eventLengthPtr = eventLength;
	    rc = TSS_EVENT2_Line_Unmarshal(&event2, &eventBinPtr, &eventLengthPtr);
	    if (rc != 0) {
		printf("ERROR: processBiosEntryPass1: error unmarshaling event %u\n", *eventNum);
	    }
	}
	if (rc == 0) {
	    if (event2.pcrIndex > TPM_BIOS_PCR) {
		printf("ERROR: processBiosEntryPass1: PCR number %u out of range\n",
		       event2.pcrIndex);
		rc = ACE_PCR_INDEX;
	    }
	}
	/* extend recalculated PCRs based on this event.  This function also does the PCR range
	   check. */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntryPass1: Processing event %u PCR %u\n",
				 *eventNum, event2.pcrIndex);
	    rc = TSS_EVENT2_PCR_Extend(biosPcrs, &event2);
	    if (rc != 0) {
		rc = ACE_EVENT;
		printf("ERROR: processBiosEntryPass1: error extending event %u\n", *eventNum);
	    }
	}
	if (rc == 0) {
	    if (vverbose) Array_Print(NULL, "processBiosEntryPass1: PCR digest", TRUE,
				      (uint8_t *)&biosPcrs[0][event2.pcrIndex].digest,
				      SHA256_DIGEST_SIZE);
	}
	/* Check to see if BIOS PCR matches within the loop.  There may be more BIOS entries than
	   required if there was a new measurement between the quote and the request for the
	   measurement log.  Ignore extra entries after BIOS PCR matches. */
	if (rc == 0) {
	    irc = memcmp((uint8_t *)&biosPcrs[0][event2.pcrIndex].digest,
			 quotePcrsBin[event2.pcrIndex],
			 SHA256_DIGEST_SIZE);
	    if (irc == 0) {
		pcrMatch[event2.pcrIndex] = 1;
		if (vverbose) printf("processBiosEntryPass1: Event %u BIOS PCR %u matched\n",
				     *eventNum, event2.pcrIndex);
	    }
	    /* if PCR does not match after extend */
	    else {
		/* if it matched previously, it can never match again because of SHA-256, so done */
		if (pcrMatch[event2.pcrIndex]) {
		    break;	/* break out of the event read loop */
		}
	    }
	}
	free(eventBin);		/* @1 */
	eventBin = NULL;
    }				/* end of eventNum loop */
    (*eventNum)--;	/* ignore the informative entry, set eventNum to 0 based */
    if (verbose) {
	if (*biosPcrVerified) {
	    if (verbose) printf("INFO: processBiosEntryPass1: %u events, BIOS PCRs matched\n",
				*eventNum);
	}
	else {
	    printf("ERROR: processBiosEntryPass1: %u events, BIOS PCRs did not match\n",
		   *eventNum);
	    if (vverbose) {
		for (i = 0 ; i < TPM_BIOS_PCR ; i++) {
		    if (!pcrMatch[i]) {
			printf("ERROR: processBiosEntryPass1: BIOS PCR %u did not match\n", i);
		    }			
		}
	    }
	}
    }
    free(eventBin);		/* @1 */
    eventBin = NULL;
    return rc;
}

#ifdef TPM_TPM12

/* processBiosEntry12Pass1() does the first pass through the client BIOS log entries.

   For each entry, it extends a PCR, starting at all zero after a reboot, and matches the
   result against the current BIOS PCRs from the quote.

   It exits when either:

   - an entry cannot be parsed
   - the calculated BIOS PCRs all match that of the quote
   - all client BIOS log entries have been processed
*/

static uint32_t processBiosEntry12Pass1(int *biosPcrVerified,	/* bool, BIOS PCRs matched */
					int *eventNum,		/* last bios entry processed */
					json_object *cmdJson,	/* client command, event log */
					uint8_t *quotePcrsBin[])  /* BIOS PCRs in quote */
{
    uint32_t 		rc = 0;
    int		irc;
    unsigned int 	i;
    int		pcrMatch[TPM_BIOS_PCR];
    unsigned char 	zeroDigest[SHA1_DIGEST_SIZE];
    TPMT_HA		biosPcrs[TPM_BIOS_PCR];	/* one bank, just sha1 */

    if (vverbose) printf("INFO: processBiosEntry12Pass1: Entry\n");
    memset(zeroDigest, 0, SHA1_DIGEST_SIZE);
    *biosPcrVerified = 0;
    for (i = 0 ; i < TPM_BIOS_PCR ; i++) {
	/* BIOS PCRs start at zero */
	biosPcrs[i].hashAlg = TPM_ALG_SHA1;
	memset((uint8_t *)&biosPcrs[i].digest, 0, SHA1_DIGEST_SIZE);
	/* any quote PCRs that are still zero start off as matching, others start not matching */
	irc = memcmp(quotePcrsBin[i], zeroDigest, SHA1_DIGEST_SIZE);
	if (irc == 0) {
	    if (vverbose) printf("processBiosEntry12Pass1: BIOS PCR %u begins matched\n", i);
	    pcrMatch[i] = 1;
	}
	else {
	    pcrMatch[i] = 0;
	}
    }
    /* Continue until either

       1 - all BIOS PCR match
       2 - a PCR that was matching became not matching, SHA-1 says it can't ever match again
       3 - there are no more events.

       Note that BIOS PCRs can verify before all events are processed.  This occurs if more events
       occurred after the quote.  In that case, remaining events are discarded at the server and
       will be retried again during the next attestation.

    */
    unsigned char *eventBin = NULL;
    for (*eventNum = 0 ; (rc == 0) && !(*biosPcrVerified) ; (*eventNum)++) {
	/* Check for all matches first, this handles the odd corner case of no BIOS measurements */
	unsigned int count = 0;
	for (i = 0 ; i < TPM_BIOS_PCR ; i++) {
	    if (pcrMatch[i]) {
		count++;
	    }
	}
	if (count == TPM_BIOS_PCR) {
	    if (vverbose) printf("processBiosEntry12Pass1: All BIOS PCR matched at event %u\n",
				 *eventNum);
	    *biosPcrVerified = 1;		/* matches, done */
	    break;
	}
	/* get the next event */
	const char *eventString;
	size_t eventLength;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&eventString,
				 *eventNum,
				 cmdJson);
	    /* Case 3: If there is no next event, done walking measurement list.  This is not a
	       json error, because the server does not know in advance how many entries the client
	       will send.  However, since BIOS PCR did not match, there is an error to be processed
	       below.  */
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntry12Pass1: done, no event %u\n", *eventNum);  
		break;			/* exit the BIOS event loop */
	    } 
	}
	/* convert the event from a string to binary */
	if (rc == 0) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    eventString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntry12Pass1: error scanning event %u\n", *eventNum);
	    }
	}
	TCG_PCR_EVENT event;	/* TPM 1.2 event log entry */
	/* unmarshal the event from binary to structure */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntryPass1: unmarshaling event %u\n", *eventNum);
	    unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
	    uint32_t eventLengthPtr = eventLength;
	    rc = TSS_EVENT_Line_Unmarshal(&event, &eventBinPtr, &eventLengthPtr);
	    if (rc != 0) {
		printf("ERROR: processBiosEntry12Pass1: error unmarshaling event %u\n", *eventNum);
	    }
	}
	if (rc == 0) {
	    if (event.pcrIndex > TPM_BIOS_PCR) {
		printf("ERROR: processBiosEntry12Pass1: PCR number %u out of range\n",
		       event.pcrIndex);
		rc = ACE_PCR_INDEX;
	    }
	}
	/* extend recalculated PCRs based on this event.  This function also does the PCR range
	   check. */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntry12Pass1: Processing event %u PCR %u\n",
				 *eventNum, event.pcrIndex);
	    rc = TSS_EVENT_PCR_Extend(biosPcrs, &event);
	    if (rc != 0) {
		rc = ACE_EVENT;
		printf("ERROR: processBiosEntry12Pass1: error extending event %u\n", *eventNum);
	    }
	}
	if (rc == 0) {
	    if (vverbose) Array_Print(NULL, "processBiosEntry12Pass1: PCR digest", TRUE,
				      (uint8_t *)&biosPcrs[event.pcrIndex].digest,
				      SHA256_DIGEST_SIZE);
	}
	/* Check to see if BIOS PCR matches within the loop.  There may be more BIOS entries than
	   required if there was a new measurement between the quote and the request for the
	   measurement log.  Ignore extra entries after BIOS PCR matches. */
	if (rc == 0) {
	    irc = memcmp((uint8_t *)&biosPcrs[event.pcrIndex].digest,
			 quotePcrsBin[event.pcrIndex],
			 SHA1_DIGEST_SIZE);
	    if (irc == 0) {
		pcrMatch[event.pcrIndex] = 1;
		if (vverbose) printf("processBiosEntry12Pass1: Event %u BIOS PCR %u matched\n",
				     *eventNum, event.pcrIndex);
	    }
	    /* if PCR does not match after extend */
	    else {
		/* if it matched previously, it can never match again because of SHA-256, so
		   done */
		if (pcrMatch[event.pcrIndex]) {
		    break;	/* break out of the event read loop */
		}
	    }
	}
	free(eventBin);		/* @1 */
	eventBin = NULL;
    }				/* end of eventNum loop */
    if (verbose) {
	if (*biosPcrVerified) {
	    if (verbose) printf("INFO: processBiosEntry12Pass1: %u events, BIOS PCRs matched\n",
				*eventNum);
	}
	else {
	    printf("ERROR: processBiosEntry12Pass1: %u events, BIOS PCRs did not match\n",
		   *eventNum);
	    if (vverbose) {
		for (i = 0 ; i < TPM_BIOS_PCR ; i++) {
		    if (!pcrMatch[i]) {
			printf("ERROR: processBiosEntry12Pass1: BIOS PCR %u did not match\n", i);
		    }			
		}
	    }
	}
    }
    free(eventBin);		/* @1 */
    eventBin = NULL;
    return rc;
}

#endif

/* processBiosEntryPass2 does the second pass through the client BIOS log entries.

 */

static uint32_t processBiosEntryPass2(const char *hostname,
				      const char *timestamp,
				      json_object *cmdJson,
				      MYSQL *mysql)
{
    uint32_t 		rc = 0;
    int 		eventNum;
    unsigned char 	*eventBin = NULL;

    for (eventNum = 1 ; (rc == 0) ; eventNum++) {
	/* get the next event */
	const char *entryString;
	size_t eventLength;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&entryString,
				 eventNum,
				 cmdJson);
	    /* Case 3: If there is no next event, done walking measurement list.  This is not a json
	       error, because the server does not know in advance how many entries the client will
	       send.  However, since BIOS PCRs did not match, there is an error to be processed
	       below.  */
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntryPass2: done, no event %u\n", eventNum);  
		break;			/* exit the BIOS event loop */
	    }
	}
	/* convert the event from a string to binary */
	if (rc == 0) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    entryString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntryPass2: error scanning event %u\n", eventNum);
	    }
	}
	TCG_PCR_EVENT2 event2;	/* TPM 2.0 hash agile event log entry */
	/* unmarshal the event from binary to structure */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntryPass2: unmarshaling event %u\n", eventNum);
	    unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
	    uint32_t eventLengthPtr = eventLength;
	    rc = TSS_EVENT2_Line_Unmarshal(&event2, &eventBinPtr, &eventLengthPtr);
	    if (rc != 0) {
		printf("ERROR: processBiosEntryPass2: error unmarshaling event %u\n", eventNum);
	    }
	}
	/* convert the event type to nul terminated ascii string */
	const char *eventTypeString;
	if (rc == 0) {
	    eventTypeString = TSS_EVENT_EventTypeToString(event2.eventType);
	}
	/* convert the event to nul terminated ascii string */
	char eventString[256];	/* matches schema */
	char *eventStringPtr;
	char *eventStringHexascii = NULL;
	if (rc == 0) {
	    if (isprint(event2.event[0])) {
		eventStringPtr = eventString;
		int length;
		if (event2.eventSize < sizeof(eventString)) {
		    length = event2.eventSize + 1;
		}
		else {
		    length = sizeof(eventString);	/* truncate */
		}
		snprintf(eventString, length, "%.*s", length, event2.event);
	    }
	    /* some events are not printable */
	    else {
		if (rc == 0) {
		    rc = Array_PrintMalloc(&eventStringHexascii,	/* freed @2 */
					   event2.event,
					   event2.eventSize);
		}
		if (rc == 0) {
		    eventStringPtr = eventStringHexascii; 
		}
	    }
	    if (vverbose) printf("processBiosEntryPass2: event %u %s\n",
				 eventNum, eventStringPtr);
	}
	uint32_t count;
	char *pcrSha1Hexascii = NULL;
	char *pcrSha256Hexascii = NULL;
	
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
		if (verbose) printf("processBiosEntryPass2: event %u unknown hash alg %04x\n",
				    eventNum, event2.digests.digests[count].hashAlg);
	    }
	}
	/* insert the event into the bioslog database */
	char query[QUERY_LENGTH_MAX];
	if (rc == 0) {
	    sprintf(query,
		    "insert into bioslog "
		    "(hostname, timestamp, entrynum, bios_entry, "
		    "pcrindex, pcrsha1, pcrsha256, "
		    "eventtype, event) "
		    "values ('%s','%s','%u','%s', "
		    "'%u','%s','%s', "
		    "'%s','%s')",
		    hostname, timestamp, eventNum, entryString,
		    event2.pcrIndex, pcrSha1Hexascii, pcrSha256Hexascii,
		    eventTypeString, eventStringPtr);
	    rc = SQ_Query(NULL,
			  mysql, query);
	}
	/* loop free */
	free(eventBin);			/* @1 */
	free(eventStringHexascii);	/* @2 */
	free(pcrSha1Hexascii);		/* @3 */
	free(pcrSha256Hexascii);	/* @4 */	
	eventBin = NULL;
	eventStringHexascii = NULL;
	pcrSha1Hexascii = NULL;
	pcrSha256Hexascii = NULL;	
    }
    /* error case free */
    free(eventBin);		/* @1 */
    return rc;
}

#ifdef TPM_TPM12

/* processBiosEntry12Pass2 does the second pass through the client BIOS log entries.

 */

static uint32_t processBiosEntry12Pass2(const char *hostname,
					const char *timestamp,
					json_object *cmdJson,
					MYSQL *mysql)
{
    uint32_t 		rc = 0;
    int 		eventNum;
    unsigned char 	*eventBin = NULL;

    for (eventNum = 0 ; (rc == 0) ; eventNum++) {
	/* get the next event */
	const char *entryString;
	size_t eventLength;
	if (rc == 0) { 
	    rc = JS_Cmd_GetEvent(&entryString,
				 eventNum,
				 cmdJson);
	    /* Case 3: If there is no next event, done walking measurement list.  This is not a json
	       error, because the server does not know in advance how many entries the client will
	       send.  However, since BIOS PCRs did not match, there is an error to be processed
	       below.  */
	    if (rc != 0) {
		rc = 0;		/* last event is not an error */
		if (vverbose) printf("processBiosEntry12Pass2: done, no event %u\n", eventNum);  
		break;			/* exit the BIOS event loop */
	    }
	}
	/* convert the event from a string to binary */
	if (rc == 0) {
	    rc = Array_Scan(&eventBin,		/* freed @1 */
			    &eventLength,
			    entryString);
	    if (rc != 0) {
		printf("ERROR: processBiosEntry12Pass2: error scanning event %u\n", eventNum);
	    }
	}
	TCG_PCR_EVENT event;	/* TPM 1.2 event log entry */
	/* unmarshal the event from binary to structure */
	if (rc == 0) {
	    if (vverbose) printf("processBiosEntry12Pass2: unmarshaling event %u\n", eventNum);
	    unsigned char *eventBinPtr = eventBin;	/* ptr that moves */
	    uint32_t eventLengthPtr = eventLength;
	    rc = TSS_EVENT_Line_Unmarshal(&event, &eventBinPtr, &eventLengthPtr);
	    if (rc != 0) {
		printf("ERROR: processBiosEntry12Pass2: error unmarshaling event %u\n", eventNum);
	    }
	}
	/* convert the event type to nul terminated ascii string */
	const char *eventTypeString;
	if (rc == 0) {
	    eventTypeString = TSS_EVENT_EventTypeToString(event.eventType);
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
		snprintf(eventString, length, "%.*s", length, event.event);
	    }
	    /* some events are not printable */
	    else {
		if (rc == 0) {
		    rc = Array_PrintMalloc(&eventStringHexascii,	/* freed @2 */
					   event.event,
					   event.eventDataSize);
		}
		if (rc == 0) {
		    eventStringPtr = eventStringHexascii; 
		}
	    }
	    if (vverbose) printf("processBiosEntry12Pass2: event %u %s\n",
				 eventNum, eventStringPtr);
	}
	char *pcrSha1Hexascii = NULL;
	char *pcrSha256Hexascii = "";
	/* convert SHA1 PCR to hexascii */
	if (rc == 0) {
	    rc = Array_PrintMalloc(&pcrSha1Hexascii,		/* freed @3 */
				   event.digest,
				   SHA1_DIGEST_SIZE);
	}
	/* insert the event into the bioslog database */
	char query[QUERY_LENGTH_MAX];
	if (rc == 0) {
	    sprintf(query,
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
	    rc = SQ_Query(NULL,
			  mysql, query);
	}
	/* loop free */
	free(eventBin);			/* @1 */
	free(eventStringHexascii);	/* @2 */
	free(pcrSha1Hexascii);		/* @3 */
	eventBin = NULL;
	eventStringHexascii = NULL;
	pcrSha1Hexascii = NULL;
    }
    /* error case free */
    free(eventBin);		/* @1 */
    return rc;
}

#endif

/* processImaEntry() processes an IMA event log entry list

   The client command has:

   {
   "command":"imaentry",
   "hostname":"cainl.watson.ibm.com",
   "nonce":"1298d83cdd8c50adb58648d051b1a596b66698758b8d0605013329d0b45ded0c",
   "imaentry":"0",
   "event0":"hexascii"
   }

   ~~

   Updates the machines table with:

   imaevents - running total of events processed, next event for incremental
   IMA PCR - current PCR 10 for incremental

   Updates the attestlog table with:

   imaevents - running total of events processed
   badimalog - event log parsing error
   imaPcrVerified - event log not verified against quote
   
   Creates an imalog table entry with:

   - hostname - the client machine name
   - boottime - client time of last boot
   - timestamp - server time of quote verification
   - eventNum - the IMA log entry number
   - eventString - the raw IMA entry as hex ascii
   
   - filename - event file name
   - badEvent - if the template data hash did not verify, or the template data could not be
   unmarshaled
   - noSig - if the template data lacked a signature
   - noKey - if the public signing key referenced by the template data is unknown
   - badSig - if the IMA entry signature did not verify

   ~~

   Client response:

   {
   "response":"imaentry"
   }
   
*/

static uint32_t processImaEntry(unsigned char **rspBuffer,	/* freed by caller */
				uint32_t *rspLength,
				json_object *cmdJson)
{
    uint32_t  	rc = 0;		/* server error, should never occur, aborts processing */
    uint32_t	crc = 0;	/* errors in client data */
    int		tpm20 = TRUE;

    if (verbose) printf("INFO: processImaEntry: Entry\n");

    /* get the command, imaentry for TPM 2.0 and imaentry12 for TPM 1.2 */
    const char *commandString;
    if (rc == 0) {
	rc = JS_ObjectGetString(&commandString, "command", cmdJson);
    }
    if (rc == 0) {
	if (strcmp(commandString, "imaentry12") == 0) {	/* TPM 1.2 */
	    tpm20 = FALSE;
	}
    }
#ifndef TPM_TPM12
    if (rc == 0) {
	if (!tpm20) {
	    printf("ERROR: processImaEntry: Client TPM 1.2 not supported\n");
	    rc = ACE_TPM12_UNSUPPORTED;
	}
    }
#endif
    /* get the first imaentry number */
    unsigned int imaEntry;
    if ((rc == 0) && (crc == 0)) {
	crc = JS_Cmd_GetImaEntry(&imaEntry, cmdJson);
    }
    /* get the client host name */
    const char *hostname = NULL;
    if ((rc == 0) && (crc == 0)) {
	crc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* get the client nonce command */
    const char *clientNonceString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&clientNonceString, "nonce", cmdJson);
    }
    /* connect to the db */
    MYSQL *mysql = NULL;
    if ((rc == 0) && (crc == 0)) {
	rc = SQ_Connect(&mysql);	/* closed @1 */	
    }
    /* get imaevents to process, and the starting IMA PCR value for this hostname */
    char 	*machineId = NULL;	/* save for the updates */
    int 	imaevents;		/* next IMA event, 0 or value for incremental validation */
    const char  *imapcr;		/* IMA PCR value from last valid IMA event log check */
    MYSQL_RES *machineResult = NULL;
    if (rc == 0) {
	const char 		*akCertificatePem = NULL;
	rc = SQ_GetMachineEntry(&machineId, 		/* freed @2 */
				NULL,			/* tpmvendor */
				NULL,			/* challenge */
				NULL,			/* attestpub */
				NULL,			/* ekcertificatepem */
				NULL,			/* ekcertificatetext */
				&akCertificatePem,	/* akcertificatepem */
				NULL,			/* akcertificatetext */
				NULL,			/* enrolled */
				NULL,			/* boottime */
				&imaevents,		/* imaevents */
				&imapcr,		/* imapcr */
				&machineResult,		/* freed @3 */
				mysql,
				hostname);
	if (rc != 0) {
	    printf("ERROR: processImaEntry: row for hostname %s does not exist in machine table\n",
		   hostname);
	}
	/* check that the host has been completely enrolled */
	else if (akCertificatePem == NULL) {
	    printf("ERROR: processImaEntry: "
		   "row for hostname %s has invalid certificate in machine table\n",
		   hostname);  
	    rc = ACE_INVALID_CERT;
	}
    }
    if (rc == 0) {
	if (vverbose) printf("processImaEntry: previous IMA PCR %s\n", imapcr);
    }
    /* get the client reported boottime, recorded during the quote, used later to determine the
       previous PCRs for this boot cycle, if any */
    MYSQL_RES 		*attestLogResult = NULL;
    char 		*attestLogId = NULL;		/* row being updated */
    const char 		*clientBootTime = NULL;
    const char 		*timestamp = NULL;
    const char 		*serverNonceString = NULL;
    const char 		*quoteVerifiedString = NULL;
    if (rc == 0) {
	rc = SQ_GetAttestLogEntry(&attestLogId,  	/* freed @4 */
				  &clientBootTime,	/* boottime */
				  &timestamp,		/* timestamp */
				  &serverNonceString,	/* nonce */
				  NULL,			/* pcrselect */
				  &quoteVerifiedString,	/* quoteverified */
				  NULL,			/* logverified */
				  &attestLogResult,	/* freed @5 */
				  mysql,
				  hostname);
	/* this is a client error, indicating a bad hostname, or a hostname for the first time */
	if (rc != 0) {
	    printf("ERROR: processImaEntry: "
		   "row for hostname %s does not exist in server database\n",
		   hostname);  
	    rc = ACE_NONCE_MISSING;
	}
	/* The DB quoteverified is used as state.  When the nonce is created, it is null, indicating
	   that the nonce has not been used to verify a quote.  At that time, an event log should
	   not be accepted yet.  After the quote, quoteverified is set true or false, indicating
	   that the quote has been verified. */    
	else if (quoteVerifiedString == NULL) {
	    printf("ERROR: processImaEntry: nonce for hostname %s has not validated a quote\n",
		   hostname);  
	    rc = ACE_QUOTE_MISSING;
	}
	/* The server uses the nonce as a sort of one time cookie.  The client echoes the quote
	   nonce with the event log and the server checks for a match.  This prevents a rogue client
	   from masquerading as a client and causing mischief by sending an incorrect event log.  It
	   assumes that the nonce is a random value that cannot be guessed by the rogue.  */
	else if (strcmp(clientNonceString, serverNonceString) != 0) {
	    printf("ERROR: processImaEntry: nonce for hostname %s from client does not match\n",
		   hostname);  
	    rc = ACE_NONCE_VALUE;
	}
    }
    /* sanity check, should never occur */
    if (rc == 0) {
	if ((clientBootTime == NULL) || (timestamp == NULL)) {
	    printf("ERROR: processImaEntry: attestlog DB entry is NULL\n");
	    rc = ASE_NULL_VALUE;
	}
    }
    /* Get the current IMA PCR value for the host name from the attestlog database.  It was
       received with the quote.
    */
    MYSQL_RES 	*attestLogPCRResult = NULL;
    const char	*quotePcrsSha1String[IMPLEMENTATION_PCR];	/* current quote, from database */
    const char	*quotePcrsSha256String[IMPLEMENTATION_PCR];	/* current quote, from database */
    if (rc == 0) {
	rc = SQ_GetAttestLogPCRs(NULL,  
				 quotePcrsSha1String,
				 quotePcrsSha256String,
				 &attestLogPCRResult,	/* freed @6 */
				 mysql,
				 hostname);
    }
    if (rc == 0) {
	if ((tpm20 && ((quotePcrsSha1String[0] == NULL) || (quotePcrsSha256String[0] == NULL))) ||
	    (!tpm20 && (quotePcrsSha1String[0] == NULL))) {
	    printf("ERROR: processImaEntry: attestlog DB entry is NULL\n");
	    rc = ASE_NULL_VALUE;
	}
    }
    /* convert previous and current IMA PCR to binary arrays for extend and compare */
    uint8_t *quoteImaPcr = NULL;
    size_t quoteImaPcrLength;
    uint8_t *previousImaPcr = NULL;
    size_t previousImaPcrLength;
    if ((rc == 0) && (crc == 0)) {
	rc = Array_Scan(&previousImaPcr,		/* freed @7 */
			&previousImaPcrLength,
			imapcr);
    }    
    if ((rc == 0) && (crc == 0)) {
	if (tpm20) {
	    rc = Array_Scan(&quoteImaPcr,			/* freed @8 */
			    &quoteImaPcrLength,
			    quotePcrsSha256String[TPM_IMA_PCR]);
	}
#ifdef TPM_TPM12	/* unsupported screened out earlier */
	else {
	    rc = Array_Scan(&quoteImaPcr,			/* freed @8 */
			    &quoteImaPcrLength,
			    quotePcrsSha1String[TPM_IMA_PCR]);
	}
#endif
    }
    /* FIXME sanity check lengths */
	
    /* The first pass checks the IMA event digest against IMA PCR.  If this fails, the event list is
       invalid, and there is no point in validating the individual entries.

       If the IMA PCR calculation verifies, the second pass below validates individual entries.
    */
    if ((rc == 0) && (crc == 0)) {
	if (verbose) printf("INFO: processImaEntry: First pass, validating IMA PCR\n");
    }
    int imaPcrVerified = 0;		/* default to false in case previous step failed */
    unsigned int lastEventNum;	/* the current IMA event being processed */
    if ((rc == 0) && (crc == 0)) {
	rc = processImaEntryPass1(&crc,			/* IMA log parsing error */
				  &imaPcrVerified,	/* bool, IMA PCR matched */
				  &lastEventNum,	/* last ima entry processed */
				  cmdJson,		/* client command */
				  tpm20,		/* TRUE for TPM 2.0 */
				  previousImaPcr,  	/* IMA PCR before the latest quote */
				  quoteImaPcr,  	/* IMA PCR in quote */
				  imaEntry);		/* first ima entry to be processed */
    }
    char query[QUERY_LENGTH_MAX];
    /* update the machines table */
    if (rc == 0) {
	/* if the IMA log verified, update the imaevents to the next event for an incremental update
	   and the imapcr to the current quote value */
	if (imaPcrVerified) {
	    if (tpm20) {
		sprintf(query,
			"update machines set imaevents = '%u', imapcr = '%s' where id = '%s'",
			lastEventNum + 1, quotePcrsSha256String[TPM_IMA_PCR], machineId);
	    }
#ifdef TPM_TPM12	/* unsupported screened out earlier */
	    else {
		sprintf(query,
			"update machines set imaevents = '%u', imapcr = '%s' where id = '%s'",
			lastEventNum + 1, quotePcrsSha1String[TPM_IMA_PCR], machineId);
	    }
#endif
	    rc = SQ_Query(NULL,
			  mysql, query);
	}
	/* on error, leave the values as is, try incremental update on the next quote */
	else {
	    printf("ERROR: processImaEntry: IMA PCR did not verify\n");
	}
    }
    /* update the attestlog table */
    int badimalog = 0;
    if (rc == 0) {
	if (crc != 0) {
	    badimalog = 1;
	    printf("ERROR: processImaEntry: IMA event log did not parse\n");
	}
	sprintf(query,
		"update attestlog set "
		"imaevents = '%u', badimalog = '%u', imaver = '%u' where id = '%s'",
		lastEventNum + 1, badimalog, imaPcrVerified, attestLogId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* The second pass matches the digest against the template data hash, then parses the template
       data, and checks for no signature, an unknown key, or a bad signature.
    */
    if (imaPcrVerified) {		/* only done if IMA PCR matches the event log */
	int imasigver;
	if ((rc == 0) && (crc == 0)) {
	    if (verbose) printf("INFO: processImaEntry: Second pass, validating IMA entries %u to %u\n",
				imaEntry, lastEventNum);
	    rc = processImaEntryPass2(&imasigver,
				      hostname,		/* for DB row */
				      clientBootTime,	/* for DB row */
				      timestamp,	/* for DB row */
				      cmdJson,		/* client command */
				      imaEntry,		/* first ima entry to be processed */
				      lastEventNum,	/* last ima entry to be processed */
				      mysql);	
	}
	if ((rc == 0) && (crc == 0)) {
	    sprintf(query,
		    "update attestlog set "
		    "imasigver = '%u' where id = '%s'",
		    imasigver, attestLogId);
	    rc = SQ_Query(NULL,
			  mysql, query);
	}	
    }
    /* create the imaentry return json */
    json_object *response = NULL;
    uint32_t rc1 = JS_ObjectNew(&response);		/* freed @1 */
    if (rc1 == 0) {
	if (rc == 0) {
	    json_object_object_add(response, "response", json_object_new_string("imaentry"));
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
    SQ_Close(mysql);				/* @1 */
    free(machineId);				/* @2 */
    SQ_FreeResult(machineResult);		/* @3 */
    free(attestLogId);				/* @4 */
    SQ_FreeResult(attestLogResult);		/* @5 */
    SQ_FreeResult(attestLogPCRResult);		/* @6 */
    free(previousImaPcr);			/* @7 */
    free(quoteImaPcr);				/* @8 */
    return rc;
}


/* processImaEntryPass1() does the first pass through the client IMA log entries.

   For each entry, it extends the previous IMA PCR (which is all zero after a reboot) and matches
   the result against the current IMA PCR from the quote.

   It exits when either:

   - an entry cannot be parsed
   - the calculated IMA PCR matches that of the quote
   - all client IMA log entries have been processed
*/

static uint32_t processImaEntryPass1(uint32_t *crc,		/* IMA log parsing error */
				     int *imaPcrVerified,	/* bool, IMA PCR matched */
				     unsigned int *eventNum,	/* last ima entry processed */
				     json_object *cmdJson,	/* client command */
				     int tpm20,
				     uint8_t *previousImaPcr,  	/* IMA PCR before the latest quote */
				     const uint8_t *currentImaPcr,  	/* IMA PCR in quote */
				     unsigned int imaEntry)	/* first ima entry to be processed */
{
    uint32_t rc = 0;
    int		irc;

    /* Initialize with the previous IMA PCR value.  It will be all zero for a new boot cycle or the
       first time for the hostname.  */
    TPMT_HA imapcr;
    memcpy(&imapcr.digest, previousImaPcr, TPM_SHA256_SIZE);
    /* Continue until either IMA PCR matches or there are no more events.  Note that IMA PCR can
       verify before all events are processed.  This occurs if more events occurred after the quote.
       In that case, remaining events are discarded at the server and will be retried again during
       the next attestation. */
    for (*eventNum = imaEntry ; (rc == 0) && (*crc == 0) && !(*imaPcrVerified) ; (*eventNum)++) {
	/* get the next event */
	const char *eventString;
	unsigned char *event = NULL;
	size_t eventLength;
	if ((rc == 0) && (*crc == 0)) { 
	    *crc = JS_Cmd_GetEvent(&eventString,
				   *eventNum,
				   cmdJson);
	    /* If there is no next event, done walking measurement list.  This is not a json error,
	       because the server does not know in advance how many entries the client will send.
	       However, since IMA PCR did not match, there is an error to be processed below.  */
	    if (*crc != 0) {
		*crc = 0;		/* last event is not an error */
		if (vverbose) printf("processImaEntryPass1: done, no event %u\n", *eventNum);  
		break;			/* exit the IMA event loop */
	    } 
	}
	/* convert the event from a string to binary */
	if ((rc == 0) && (*crc == 0)) {
	    *crc = Array_Scan(&event,			/* freed @2 */
			      &eventLength,
			      eventString);
	    if (*crc != 0) {
		printf("ERROR: processImaEntryPass1: error scanning event %u\n", *eventNum);
	    }
	}
	unsigned char *eventFree = event;	/* because IMA_Event_ReadBuffer moves the buffer */
	ImaEvent imaEvent;
	/* unmarshal the event */
	if ((rc == 0) && (*crc == 0)) {
	    if (vverbose) printf("processImaEntryPass1: unmarshaling event %u\n", *eventNum);
	    int endOfBuffer;	/* unused */
	    *crc = IMA_Event_ReadBuffer(&imaEvent,		/* freed @1 */
					&eventLength,
					&event,
					&endOfBuffer,
					FALSE,	/* client sends to server in HBO */
					TRUE);	/* parse template data now so errors will not occur
						   in the 2nd pass */
	    if (*crc != 0) {
		printf("ERROR: processImaEntryPass1: error unmarshaling event %u\n", *eventNum);
	    }
	}
	if ((rc == 0) && (*crc == 0)) {
	    if (vverbose) IMA_Event_Trace(&imaEvent, FALSE);
	}
	/* extend the IMA event */
	if ((rc == 0) && (*crc == 0)) {
	    if (tpm20) {
		rc = IMA_Extend(&imapcr, &imaEvent, TPM_ALG_SHA256);
	    }
	    else {
		rc = IMA_Extend(&imapcr, &imaEvent, TPM_ALG_SHA1);
	    }
	    if (rc != 0) {
		printf("ERROR: processImaEntryPass1: error extending event %u\n", *eventNum);
	    }
	}
	/* trace the updated IMA PCR value */
	if ((rc == 0) && (*crc == 0)) {
	    if (tpm20) {
		if (vverbose) TSS_PrintAll("processImaEntryPass1: Updated IMA PCR",
					   (uint8_t *)&imapcr.digest, SHA256_DIGEST_SIZE);
	    }
	    else {
		if (vverbose) TSS_PrintAll("processImaEntryPass1: Updated IMA PCR",
					   (uint8_t *)&imapcr.digest, SHA1_DIGEST_SIZE);
	    }
	}
	/* Check to see if IMA PCR matches within the loop.  There may be more IMA entries that
	   required if there was a new measurement between the quote and the request for the
	   measurement log.  Ignore extra entries after IMA PCR matches. */
	
	if ((rc == 0) && (*crc == 0)) {
	    if (tpm20) {
		irc = memcmp((uint8_t *)&imapcr.digest, currentImaPcr, TPM_SHA256_SIZE);
	    }
	    else {
		irc = memcmp((uint8_t *)&imapcr.digest, currentImaPcr, TPM_SHA1_SIZE);
	    }
	    if (irc == 0) {
		if (verbose) printf("INFO: processImaEntryPass1: IMA PCR verified\n");
		*imaPcrVerified = 1;		/* matches, done */
	    }
	}
	IMA_Event_Free(&imaEvent);	/* @1 */
	free(eventFree);		/* @2 */
	event = NULL;
    }	/* end event for loop */
    (*eventNum)--;	/* because the for loop increments, even if exiting the loop */
    return rc;
}

/* processImaEntryPass2() does the second pass through the client IMA log entries.

   For each entry, it does these checks:

   - If the digest is all zero, template_data is ignored, as it is intentionally invalid
   - Checks the digest against the template data
   - Unmarshals the template_data
   - Checks for the presence of a signature
   - Checks for a valid public key
   - Checks the signature
*/

static uint32_t processImaEntryPass2(int *imasigver,
				     const char *hostname,	/* for DB row */
				     const char *boottime,	/* for DB row */
				     const char *timestamp,	/* for DB row */
				     json_object *cmdJson,	/* client command */
				     unsigned int imaEntry,	/* first ima entry to be processed */
				     unsigned int lastEventNum,	/* last ima entry to be processed */
				     MYSQL *mysql)		/* opened DB */
{
    uint32_t 	rc = 0;
    uint32_t	vrc = 0;	/* errors in verification */

    *imasigver = TRUE;
    
    unsigned char 	zeroDigest[TPM_SHA1_SIZE];	/* compare to SHA-1 digest in event log */
    if (rc == 0) {
	if (verbose) printf("INFO: processImaEntryPass2: Second pass, template data\n");
	memset(zeroDigest, 0, TPM_SHA1_SIZE);
    }
    unsigned int eventNum;			/* the current IMA event number being processed */
    ImaEvent imaEvent;				/* the current IMA event being processed */
    IMA_Event_Init(&imaEvent);			/* so the first free works */
    unsigned char *eventBin = NULL;		/* so the first free works */
    unsigned char *eventFree = eventBin;	/* because IMA_Event_ReadBuffer moves the buffer */

    /* iterate through entries received from the client */
    for (eventNum = imaEntry ; (rc == 0) && (eventNum <= lastEventNum) ; eventNum++) {

	/* get the next event */
	const char *eventString;
	size_t eventBinLength;
	/* add a free at the beginning to handle the loop 'continue' case */
	IMA_Event_Free(&imaEvent);		/* @1 */
	free(eventFree);			/* @2 */
	eventFree = NULL;
	/* get the next IMA event from the client json */
	if (rc == 0) { 
	    vrc = JS_Cmd_GetEvent(&eventString,
				  eventNum,
				  cmdJson);
	    /* if there is no next event, done walking measurement list */
	    if (vrc != 0) {	/* FIXME this should never happen */
		if (vverbose) printf("processImaEntryPass2: done, no event %u\n", eventNum);  
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
	    if (vverbose) printf("processImaEntryPass2: unmarshaling event %u\n", eventNum);
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
		if (vverbose) printf("processImaEntryPass2: skipping zero event %u\n", eventNum);
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
				       &imaEvent,	/* the current IMA event being processed */
				       eventNum); 	/* the current IMA event number */
	}
	/* if the event template hash validated and it unmarshaled, the file name is valid.  Save it
	   for the imalog DB row. */
	if ((rc == 0) && !badEvent) {
	    filename = (char *)imaTemplateData.fileName;
	}
	if (imaEvent.nameInt == IMA_SIG) {
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
					imaRsaPkey[imaKeyNumber],	/* public key token, openssl
									   format */
					eventNum);	/* the current IMA event number */
	    }
	}
	/* no signature, record something in DB */
	else {
	    noSig = TRUE;
	    noKey = TRUE;
	    badSig = TRUE;
	}
	if (badEvent || noSig || noKey || badSig) {
	    *imasigver = FALSE;
	}
	/* insert the event into the imalog database */
	char query[QUERY_LENGTH_MAX];
	if (rc == 0) {
	    sprintf(query,
		    "insert into imalog "
		    "(hostname, boottime, timestamp, entrynum, ima_entry, "
		    "filename, badevent, nosig, nokey, badsig) "
		    "values ('%s','%s','%s','%u','%s', "
		    "'%s','%u','%u','%u','%u')",
		    hostname, boottime, timestamp, eventNum, eventString,
		    filename, badEvent, noSig, noKey, badSig);
	    rc = SQ_Query(NULL,
			  mysql, query);
	    
	}
	IMA_Event_Free(&imaEvent);		/* @1 */
	free(eventFree);			/* @2 */
	eventFree = NULL;
    }		/* for each event */
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
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *tpmVendorString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&tpmVendorString , "tpmvendor", cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *ekCertString = NULL;	/* hexascii */
    if (rc == 0) {
	rc = JS_ObjectGetString(&ekCertString, "ekcert", cmdJson);
    }
    /* get the client attestation key TPMT_PUBLIC from the command */
    const char *attestPubString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&attestPubString, "akpub", cmdJson);
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
	sprintf(query,
		"insert into machines "
		"(hostname, tpmvendor, ekcertificatepem, ekcertificatetext, "
		"challenge, attestpub) "
		"values ('%s','%s %s','%s','%s','%s','%s')",
		hostname, tpmVendorString, "TPM 2.0",
		ekCertificatePemString, ekCertificateX509String,
		challengeString, attestPubString);
	rc = SQ_Query(NULL,
		      mysql, query);
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
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *tpmVendorString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&tpmVendorString , "tpmvendor", cmdJson);
    }
    /* get the client EK certificate from the command */
    const char *ekCertString = NULL;	/* hexascii */
    if (rc == 0) {
	rc = JS_ObjectGetString(&ekCertString, "ekcert", cmdJson);
    }
    /* get the client attestation key TPM_PUBKEY from the command */
    const char *attestPubString12 = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&attestPubString12, "akpub", cmdJson);
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
			     (MarshalFunction_t)TSS_TPMT_PUBLIC_Marshal);
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
	sprintf(query,
		"insert into machines "
		"(hostname, tpmvendor, ekcertificatepem, ekcertificatetext, "
		"challenge, attestpub) "
		"values ('%s','%s %s','%s','%s','%s','%s')",
		hostname, tpmVendorString, "TPM 1.2",
		ekCertificatePemString, ekCertificateX509String,
		challengeString, attestPubString20);
	rc = SQ_Query(NULL,
		      mysql, query);
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
	rc = JS_ObjectGetString(&hostname, "hostname", cmdJson);
    }
    /* get the decrypted challenge from the command */
    const char *challengeString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&challengeString, "challenge", cmdJson);
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
	rc = TPMT_PUBLIC_Unmarshal(&attestPub, &tmpptr, &tmpLengthPtr, TRUE);
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
	sprintf(query,
		"update machines set akcertificatepem = '%s', akcertificatetext = '%s', "
		"imaevents = '%u' where id = '%s'",
		akCertPemString, akX509CertString , 0, machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
    /* construct a enrollment timestamp and add to machine DB */
    char enrolledTime[80];
    if (rc == 0) {
	getTimeStamp(enrolledTime, sizeof(enrolledTime));
    }
    if (rc == 0) {
	sprintf(query,
		"update machines set enrolled = '%s' where id = '%s'",
		enrolledTime, machineId);
	rc = SQ_Query(NULL,
		      mysql, query);
    }
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
	rc = TPMT_PUBLIC_Unmarshal(attestPub, &tmpptr, &tmpLengthPtr, TRUE);
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
	rc = TSS_TPM_PUBKEY_Unmarshal(attestPub12, &tmpptr, &tmpLengthPtr);
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
			     (MarshalFunction_t)TSS_TPM2B_ID_OBJECT_Marshal);
    }
    /* secret to string */
    if (rc == 0) {
	rc = Structure_Print(secretString,		/* freed by caller */
			     secret,
			     (MarshalFunction_t)TSS_TPM2B_ENCRYPTED_SECRET_Marshal);
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
	rc = TSS_TPM_PUBKEY_Marshal(attestPub, &written, &buffer, &size);
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
	rc = TSS_TPM_EK_BLOB_ACTIVATE_Marshal(&a1Activate, &written, &buffer, &size);
	b1Blob.blobSize = written;
    }
    uint8_t 	decBlob[MAX_RSA_KEY_BYTES];
    size_t	decBlobLength;
    /* marshal the TPM_EK_BLOB */
    if (rc == 0) {
	uint16_t written = 0;
	uint8_t *buffer = decBlob;
	uint32_t size = sizeof(decBlob);	/* max size */
	rc = TSS_TPM_EK_BLOB_Marshal(&b1Blob, &written, &buffer, &size);
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
			       ImaEvent *imaEvent,	/* the current IMA event being processed */
			       int eventNum)	/* the current IMA event number being processed */
{
    uint32_t 	rc = 0;

    /* unmarshal the template data */
    if (rc == 0) {
	rc = IMA_TemplateData_ReadBuffer(imaTemplateData,
					 imaEvent,
					 TRUE);	/* littleEndian */
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

    if (imaTemplateData->sigLength != 0) {
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
    
    if (vverbose) Array_Print(NULL, "getImaPublicKeyIndex: required signature fingerprint", TRUE,
			      imaTemplateData->sigHeader + 3, 4);	/* FIXME magic numbers */
    for (*imaKeyNumber = 0 ; (rc == 0) && (*imaKeyNumber < imaKeyCount) ; (*imaKeyNumber)++) {
	irc = memcmp(imaTemplateData->sigHeader + 3, imaFingerprint[*imaKeyNumber], 4);
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

/* verifyImaSignature() verifies template data signature.

*/

uint32_t verifyImaSignature(uint32_t *badSig,
			    const ImaTemplateData *imaTemplateData,	/* unmarshaled template
									   data */
			    RSA  *rsaPkey,	/* public key token, openssl format */
			    int eventNum)	/* the current IMA event number being processed */
{
    uint32_t 	rc = 0;
    int 	irc;

    irc = RSA_verify(imaTemplateData->hashNid,
		     imaTemplateData->fileDataHash, imaTemplateData->fileDataHashLength,
		     imaTemplateData->signature, imaTemplateData->signatureSize,
		     rsaPkey);
    /* if signature verification fails, add an entry to the ima_log db badsig */
    if (irc == 1) {
	if (verbose) printf("INFO: verifyImaSignature: signature verified, event  %u\n", eventNum);
	*badSig = FALSE;
    }
    else {
	printf("ERROR: verifyImaSignature: Error, signature did not verify, event %u\n",
	       eventNum);
	*badSig = TRUE;
    }
    return rc;
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
    exit(1);	
}
