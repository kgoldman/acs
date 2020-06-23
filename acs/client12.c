/********************************************************************************/
/*										*/
/*			TPM 1.2 Attestation - Client   				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: client12.c 1607 2020-04-28 21:35:05Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2020					*/
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
#include <limits.h>
#include <time.h>

#include <unistd.h>
#include <sys/wait.h>

#include <json/json.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssmarshal12.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/Unmarshal12_fp.h>
#include "cryptoutils.h"

#ifndef TPM_ACS_NOIMA
#include "imalib.h"
#endif

#include "config.h"
#include "commonerror.h"
#include "clientjson.h"
#include "clientjson12.h"
#include "commonjson.h"
#include "clientsocket.h"
#include "eventlib.h"
#include "commonutils.h"
#include "commontss12.h"
#include "clientlocal.h"

/* local function prototypes */

static void printUsage(void);
static uint32_t saveNonce(const char *nonceString,
			  const char *pcrSelectString);
static uint32_t loadNonce(char **nonceStringSaved,
			  char **pcrSelectStringSaved);
static uint32_t getNonce(json_object **nonceResponseJson,
			 const char *hostname,
			 short port,
			 const char *machineName,
			 char *boottimeString,
			 size_t boottimeStringLen);
static uint32_t parseNonceResponse(const char **nonceString,
				   const char **pcrSelectString,
				   const char **biosEntryString,
				   const char **imaEntryString,
				   json_object *nonceResponseJson);
static uint32_t createQuote12(json_object **quoteResponseJson,
			      const char *akFilename,
			      const char *hostname,
			      short port,
			      const char *machineName,
			      const char *nonceString,
			      const TPM_PCR_SELECTION *pcrSelection,
			      const char *biosInputFilename,
			      const char *biosEntryString,
			      const char *imaInputFilename,
			      int	littleEndian,
			      const char *imaEntryString,
			      const char *srkPassword);
static uint32_t addBiosEntry(json_object *command,
			     const char *biosInputFilename,
			     const char *biosEntryString);
static uint32_t addImaEntry(json_object *command,
			    const char *imaInputFilename,
			    int		littleEndian,
			    const char *imaEntryString);
static TPM_RC runQuote12(TPM_PCR_INFO_SHORT 	*pcrData,
			 uint32_t 		*versionInfoSize,
			 TPM_CAP_VERSION_INFO 	*versionInfo,
			 uint32_t 		*signatureSize,
			 uint8_t 		*signature,
			 const unsigned char 	*nonceBin,
			 const TPM_PCR_SELECTION *pcrSelection,
			 TPM_KEY12 		*attestKey,
			 const char 		*srkPassword);
uint32_t getBootTime(char *boottime,
		     size_t boottimeMax);

int vverbose = 0;
int verbose = 0;

int main(int argc, char *argv[])
{
    int rc = 0;
    int	i;    		/* argc iterator */
    
    /* command line argument defaults */
    const char *boottimeFileName = NULL;
    char boottimeString[128];
    const char *biosInputFilename = NULL;
    
#ifndef TPM_ACS_NOIMA
    const char *imaInputFilename = NULL;
    int 	littleEndian = TRUE;
#endif
    const char *hostname = "localhost";		/* default server */
    const char 	*portString = NULL;		/* server port */
    short 	port = 2323;			/* default server */
    const char *machineName = NULL;		/* default use gethostname() */
    const char 	*aikFilename = AK_FILENAME;
    char 	aikFullName[256];
    const char 	*srkPassword = NULL;  

    unsigned int passes = 1;			/* pass counter, for debug */
    unsigned int passNumber;
    int		connectionOnly = 0;		/* for server debug */
    int		nonceOnly = 0;			/* for server debug */
    int		quoteOnly = 0;			/* for server debug */
    int		badQuote = 0;			/* for server debug */
    int		makeBootTime = 0;		/* to defeat incremental event log */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    /* do this here, because the minimal TSS does not have crypto */
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms();
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1"); /* default traces TSS errors */
    /* get the socket port number as a string */
    portString = getenv("ACS_PORT");
    if (portString != NULL) {
        sscanf(portString , "%hu", &port);
    }
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
		if (strlen(machineName) > 50) {
		    printf("ERROR: Machinename parameter limited to less than 50 characters\n");
		    exit(1);
		}
	    }
	    else {
		printf("ERROR: Missing parameter for -ma\n");
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
	else if (strcmp(argv[i],"-bf") == 0) {
	    i++;
	    if (i < argc) {
		boottimeFileName = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -bf\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ifb") == 0) {
	    i++;
	    if (i < argc) {
		biosInputFilename = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -ifb\n");
		printUsage();
	    }
	}
#ifndef TPM_ACS_NOIMA
	else if (strcmp(argv[i],"-ifi") == 0) {
	    i++;
	    if (i < argc) {
		imaInputFilename = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -ifi\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-be") == 0) {
	    littleEndian = FALSE; 
	}
#endif
	else if (strcmp(argv[i],"-co") == 0) {
	    connectionOnly = 1;
	}
	else if (strcmp(argv[i],"-no") == 0) {
	    nonceOnly = 1;
	}
	else if (strcmp(argv[i],"-qo") == 0) {
	    quoteOnly = 1;
	}
	else if (strcmp(argv[i],"-bq") == 0) {
	    badQuote = 1;
	}
	else if (strcmp(argv[i],"-bt") == 0) {
	    makeBootTime = 1;
	}
	else if (strcmp(argv[i],"-p") == 0) {
	    i++;
	    if (i < argc) {
		passes = atoi(argv[i]);
	    }
	    else {
		printf("-p option needs a value\n");
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
    /* shared with clientenroll12 */
    rc = makeAkFilenames(NULL,
			 aikFullName,
			 sizeof(aikFullName),
			 NULL,			 
			 aikFilename,
			 machineName);
    if (rc != 0) {
	exit(1);
    }
    /* get the optional bootTime command line argument.  This is used for containers, where the
       actual container start time is not available */
    if (boottimeFileName == NULL) {
	boottimeString[0] = '\0';	/* flag that boottime should come from OS */
    }
    else {
	unsigned char *data = NULL;
	size_t length;
	rc = TSS_File_ReadBinaryFile(&data,	/* freed @1 */
				     &length,
				     boottimeFileName);
	if (rc != 0) {
	    printf("ERROR: cannot open %s\n", boottimeFileName);
	    exit(1);
	}
	if (length > (sizeof(boottimeString) - 1)) {
	    printf("ERROR: %s contents length %lu too large\n",
		   boottimeFileName, (unsigned long)length);
	    exit(1);
	}
	if (length == 0) {
	    printf("ERROR: %s length 0\n", boottimeFileName);
	    exit(1);
	}
	memcpy(boottimeString, data, length);
	boottimeString[length-1] = '\0';	/* remove the newline */
	free(data);		/* @1 */
    }
    clock_t nonceStart;
    clock_t nonceEnd;
    double nonceDiff = 0;;
    clock_t quoteStart;
    clock_t quoteEnd;
    double quoteDiff = 0;
    clock_t totalStart;
    clock_t totalEnd;
    double totalDiff = 0;

    for (passNumber = 0 ; passNumber < passes ; passNumber++) {
	/* randomize the start time if running more than one pass */
	if (passes > 1) {
	    uint32_t usec;
	    RAND_bytes((unsigned char *)&usec, sizeof(uint32_t));
	    usec %= 1000000;
	    usleep(usec);
	}
	/* if makeBootTime is true, override the real boot time and thus defeat the incremental
	   event log optimization */
	if ((rc == 0) && makeBootTime) {
	    unsigned char boottimeBin[4];
	    /* generate binary random value */
	    int irc = RAND_bytes(boottimeBin, sizeof(boottimeBin));
	    /* convert to boottimeBintext for the response */
	    time_t timet = (time_t)*(uint32_t *)boottimeBin;
	    struct tm *tmptr = gmtime(&timet);
	    strftime(boottimeString, sizeof(boottimeString), "%Y-%m-%d %H:%M:%S", tmptr);
	    if (irc != 1) {
		printf("ERROR: RAND_bytes failed\n");
		rc = ACE_OSSL_RAND;
	    }
	}
	
	totalStart = time(NULL);
	/* get the nonce from the server */
	json_object *nonceResponseJson = NULL;		/* @1 */
	const char *nonceString;
	const char *pcrSelectString;
	const char *biosEntryString = "0";
	const char *imaEntryString = "0";

	/* get the quote nonce and pcr selection from the response */
	if (!connectionOnly && !quoteOnly) {
	    nonceStart = time(NULL);
	    if (rc == 0) {
		rc = getNonce(&nonceResponseJson,	/* freed @1 */
			      hostname, port,
			      machineName,
			      boottimeString,
			      sizeof(boottimeString));
	    }
	    if (rc == 0) {
		rc = parseNonceResponse(&nonceString,
					&pcrSelectString,
					&biosEntryString,
					&imaEntryString,
					nonceResponseJson);
	    }
	    nonceEnd = time(NULL);
	}
	if ((rc == 0) && badQuote) {
	    /* induce a quote failure by flipping a nonce bit.  Use an LSB so it remains
	       printable */
	    ((char *)(nonceString))[0] ^= 0x01;		
	}
	/* for debug, if nonce only, save the nonce and PCR select for subsequent testing */
	if ((rc == 0) && nonceOnly) {
	    rc = saveNonce(nonceString, pcrSelectString);
	}
	/* create quote */
	quoteStart = time(NULL);
	char *nonceStringSaved = NULL;			/* @5 */
	char *pcrSelectStringSaved = NULL;
	if ((rc == 0) && (quoteOnly)) {
	    rc = loadNonce(&nonceStringSaved,		/* freed @4 */
			   &pcrSelectStringSaved);	/* freed @5 */
	    nonceString = nonceStringSaved;
	    pcrSelectString = pcrSelectStringSaved;
	}
	json_object *quoteResponseJson = NULL;		/* @2 */
	TPM_PCR_SELECTION pcrSelection;
	if ((rc == 0) && !connectionOnly && !nonceOnly) {
	    /* the server returns a TPM 1.2 TPM_PCR_SELECTION */
	    rc = Structure_Scan(&pcrSelection,
				(UnmarshalFunction_t)TSS_TPM_PCR_SELECTION_Unmarshalu,
				pcrSelectString);
	}
	if ((rc == 0) && !connectionOnly && !nonceOnly) {

	    rc = createQuote12(&quoteResponseJson,	/* freed @2 */
			       aikFullName,
			       hostname, port,
			       machineName,
			       nonceString, &pcrSelection,
			       biosInputFilename, biosEntryString,
			       imaInputFilename, littleEndian, imaEntryString,
			       srkPassword);
	}
	quoteEnd = time(NULL);
	if ((rc == 0) && connectionOnly) {
	    int sock_fd = -1;		/* error value, for close noop */
	    if (rc == 0) {
		rc = Socket_Open(&sock_fd, hostname, port);
	    }
	    Socket_Close(sock_fd);
	}
	JS_ObjectFree(nonceResponseJson);	/* @1 */
	JS_ObjectFree(quoteResponseJson);	/* @2 */
	free(nonceStringSaved);			/* @4 */
	free(pcrSelectStringSaved);		/* @5 */
	if (passes > 1) {
	    printf("End pass %u\n", passNumber+1);
	}
	nonceDiff += difftime(nonceEnd, nonceStart);
	quoteDiff += difftime(quoteEnd, quoteStart);
	totalEnd = time(NULL);
	totalDiff += difftime(totalEnd, totalStart);
    }	/* end pass count */

    if (passes > 1) {
	printf("\n");
	printf("Nonce time \t\t%f\n", nonceDiff);
	printf("Quote time \t\t%f\n", quoteDiff);
	printf("Total time \t\t%f\n", totalDiff);
	printf("\n");
	printf("Nonce time per pass \t\t%f\n", nonceDiff / passes);
	printf("Quote time per pass \t\t%f\n", quoteDiff / passes);
	printf("Total time per pass \t\t%f\n", totalDiff / passes);
	printf("\n");
    }
    return rc;
}

/* saveNonce() saves the nonce and PCR select in temporary files.

   This is a server debug tool, permitting client commands to be sent out of order.
*/

static uint32_t saveNonce(const char *nonceString,
			  const char *pcrSelectString)
{
    uint32_t rc = 0;

    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile((const uint8_t *)nonceString,
				      strlen(nonceString) +1,
				      CLIENT_NONCE_FILENAME);
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile((const uint8_t *)pcrSelectString,
				      strlen(pcrSelectString) +1,
				      CLIENT_PCRSELECT_FILENAME);
    }
    return rc;
}

static uint32_t loadNonce(char **nonceStringSaved,
			  char **pcrSelectStringSaved)
{
    uint32_t rc = 0;
    size_t length;

    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile((uint8_t **)nonceStringSaved,
				     &length,
				     CLIENT_NONCE_FILENAME);
	if (rc != 0) {
	    printf("ERROR: loadNonce: cannot open %s\n", CLIENT_NONCE_FILENAME);
	}
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile((uint8_t **)pcrSelectStringSaved,
				     &length,
				     CLIENT_PCRSELECT_FILENAME);
	if (rc != 0) {
	    printf("ERROR: loadNonce: cannot open %s\n", CLIENT_PCRSELECT_FILENAME);
	}
    }
    return rc;
}

/* getNonce() sends a nonce request to the server.  It returns the nonce and requested PCR selection
   bitmap.

   {
   "command":"nonce12",
   "hostname":"cainl.watson.ibm.com",
   "userid":"kgold"
   "boottime":"2016-03-21 09:08:25"
   }

   The server response is of the form:
   
   {
   "response":"nonce",
   "nonce":"5ef7c0cf2bc1909d27d1acf793a5fd252be7bd29aca6ea191a4f40a60f814b00",
   "pcrselect":"00000002000b03ff0000000403000400"
   "biosentry":"0"
   "imaentry":"0"

   or
   
   "biosentry":"-1",
   "imaentry":"n"	or incremental
   }

*/

static uint32_t getNonce(json_object **nonceResponseJson,	/* freed by caller */
			 const char *hostname,
			 short port,
			 const char *machineName,
			 char *boottimeString,
			 size_t boottimeStringLen)
{
    uint32_t 	rc = 0;
    uint32_t 	cmdLength;
    uint8_t 	*cmdBuffer = NULL;
    uint32_t 	rspLength;
    uint8_t 	*rspBuffer = NULL;
    
    if (verbose) printf("INFO: getNonce\n");
    /* return the boot time for the command packet.  This is done at the 'local' layer because
       the upper layer may not have access to the clock. */
    if (rc == 0) {
	/* if the upper layer already determined the boot time, leave it unaltered */
	if (boottimeString[0] == '\0') {
	    rc = getBootTime(boottimeString, boottimeStringLen);
	}
    }
    /* construct the get nonce command packet */
    if (rc == 0) {
	rc = JS_Cmd_Nonce(&cmdLength,
			  (char **)&cmdBuffer,		/* freed @1 */
			  "nonce12",			/* command */
			  machineName,
			  boottimeString);
    }
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,	/* freed @2 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream response to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(nonceResponseJson,		/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: getNonce: response", *nonceResponseJson);
    }
    if (rc == 0) {
	rc = JS_Rsp_Nonce(*nonceResponseJson);
    }
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
    return rc;
}

/* parseNonceResponse() parses the nonce response.  It returns the nonce, PCR select, and BIOS and
   IMA entry requests.

   Format is:

   "response":"nonce",
   "nonce":"9f86c24f07e946f380d8d0b4cabef9eb78e97ba78a7a9383ccad38b0e48aae6e",
   "pcrselect":"00000002000b03ff0700000403000000",
   "biosentry":"0",
   "imaentry":"0"

*/

static uint32_t parseNonceResponse(const char **nonceString,
				   const char **pcrSelectString,
				   const char **biosEntryString,
				   const char **imaEntryString,
				   json_object *nonceResponseJson)
{
    uint32_t 	rc = 0;

    if (vverbose) printf("INFO: parseNonceResponse\n");
    if (rc == 0) {
	rc = JS_ObjectGetString(nonceString, "nonce", ACS_JSON_HASH_MAX,
				nonceResponseJson);
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(pcrSelectString, "pcrselect", ACS_JSON_PCRSELECT_MAX,
				nonceResponseJson);
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(biosEntryString, "biosentry", ACS_JSON_BOOL_MAX,
				nonceResponseJson);
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(imaEntryString, "imaentry", ACS_JSON_BOOL_MAX,
				nonceResponseJson);
    }
    return rc;
}



/* createQuote12() runs a TPM quote, and sends the quote command to the server.  

   "command":"quote",
   "hostname":"cainl.watson.ibm.com",
   "boottime":"2016-03-21 09:08:25"
   "quoted":"hexascii",
   "signature":"hexascii",
   }
   {
   "response":"quote"
   }

*/

static uint32_t createQuote12(json_object **quoteResponseJson,	/* freed by caller */
			      const char *akFilename,
			      const char *hostname,
			      short port,
			      const char *machineName,
			      const char *nonceString,
			      const TPM_PCR_SELECTION *pcrSelection,
			      const char *biosInputFilename,
			      const char *biosEntryString,
			      const char *imaInputFilename,
			      int	littleEndian,
			      const char *imaEntryString,
			      const char *srkPassword)
{
    uint32_t 	rc = 0;
    if (verbose) printf("INFO: createQuote12\n");
    if (vverbose) printf("createQuote12: nonce %s\n", nonceString);
    if (vverbose) printf("createQuote12: biosEntryString %s\n", biosEntryString);
    if (vverbose) printf("createQuote12: biosInputFilename %s\n", biosInputFilename);
    /* convert nonce to binary and use as qualifyingData */
    unsigned char *nonceBin = NULL;
    size_t nonceLen;
    if (rc == 0) {
	rc = Array_Scan(&nonceBin,		/* freed @1 */
			&nonceLen,
			nonceString);
    }
    TPM_KEY12 attestKey;	/* quote signing key */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&attestKey,
				    (UnmarshalFunction_t)TSS_TPM_KEY12_Unmarshalu,
				    akFilename);
    }
    /* run the TPM_Quote2 using the supplied nonce and pcrSelect.
       
       Returns the TPM_Quote2 outputs in binary
    */
    TPM_PCR_INFO_SHORT pcrData;
    uint32_t versionInfoSize;
    TPM_CAP_VERSION_INFO versionInfo;
    uint32_t signatureBinSize;
    uint8_t signatureBin[MAX_RSA_KEY_BYTES];
    if (rc == 0) {
	rc = runQuote12(&pcrData,
			&versionInfoSize,
			&versionInfo,
			&signatureBinSize,
			signatureBin,
			nonceBin,
			pcrSelection,
			&attestKey,		/* quote signing key */
			srkPassword);
    }
    /* pcrData to string */
    char *pcrDataString = NULL;
    if (rc == 0) {
	rc = Structure_Print(&pcrDataString, 		/* freed @2 */
			     &pcrData,
			     (MarshalFunction_t)TSS_TPM_PCR_INFO_SHORT_Marshalu);
    }
    /* versionInfo to string */
    char *versionInfoString = NULL;
    if (rc == 0) {
	rc = Structure_Print(&versionInfoString, 	/* freed @3 */
			     &versionInfo,
			     (MarshalFunction_t)TSS_TPM_CAP_VERSION_INFO_Marshalu);
    }
    /* signature array to string */
    char *signatureString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&signatureString,	/* freed @4 */
			       signatureBin,
			       signatureBinSize);
    }
    /*
       Construct the Quote client to server command
    */
    json_object *command = NULL;
    if (rc == 0) {
	rc = JS_Cmd_NewQuote12(&command,		/* freed @7 */
			       machineName,
			       pcrDataString,
			       versionInfoString,
			       signatureString);
    }
    /* add the BIOS event log to the response if requested */
    if (rc == 0) {
	rc = addBiosEntry(command, biosInputFilename, biosEntryString);
    }
    /* adds the IMA events from the event log file 'imaInputFilename' */
    if (rc == 0) {
	rc = addImaEntry(command, imaInputFilename, littleEndian, imaEntryString);
    }
    uint32_t cmdLength;
    uint8_t *cmdBuffer = NULL;
    uint32_t rspLength;
    uint8_t *rspBuffer = NULL;
    if (rc == 0) {
	rc = JS_ObjectSerialize(&cmdLength,
				(char **)&cmdBuffer,	/* freed @3 */
				command);		/* @1 */
    }
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,		/* freed @6 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse response json stream to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(quoteResponseJson,		/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: createQuote12: response", *quoteResponseJson);
    }
    if (rc == 0) {
	rc = JS_Rsp_Quote(*quoteResponseJson);
    }
    free(nonceBin);			/* @1 */
    free(pcrDataString);		/* @2 */
    free(versionInfoString);		/* @3 */
    free(signatureString);		/* @4 */
    free(cmdBuffer);			/* @5 */
    free(rspBuffer);			/* @6 */
    return rc;
}

/* addBiosEntry() adds the BIOS events from the event log file 'biosInputFilename'.

   It is conditional on the server request json

   "event1":"hexascii",
*/
   
static uint32_t addBiosEntry(json_object *command,
			     const char *biosInputFilename,
			     const char *biosEntryString)
{
    uint32_t 	rc = 0;
    
    if (vverbose) printf("addBiosEntry: Entry\n");
    int biosEntry;	/* response as an integer */
    if (rc == 0) {
	sscanf(biosEntryString, "%u", &biosEntry);
    }    
    if (rc == 0) {
	if (biosEntry >= 0) {
	    if (vverbose) printf("addBiosEntry: start with biosEntry %d\n", biosEntry);
	}
	else {
	    if (vverbose) printf("addBiosEntry: no BIOS measurements required\n");
	    return 0;
	}
    }
    if (biosInputFilename != NULL) {
    	/* open the BIOS event log file */
	FILE *infile = NULL;
	if (rc == 0) {
	    infile = fopen(biosInputFilename,"rb");	/* closed @2 */
	    if (infile == NULL) {
		printf("ERROR: addBiosEntry: Unable to open event log file '%s'\n",
		       biosInputFilename);
		rc = ACE_FILE_OPEN;
	    }
	}
	TCG_PCR_EVENT 		event;		/* TPM 1.2 format header event */
	int 			endOfFile = FALSE;
	/* scan each measurement 'line' in the binary */
	unsigned int 		lineNum;	/* FIXME no incremental log yet */
	for (lineNum = 0 ; !endOfFile && (rc == 0) ; lineNum++) {
	    /* read a TCG_PCR_EVENT event line */
	    if (rc == 0) {
		rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
	    }
	    /* debug tracing */
	    if (vverbose && !endOfFile && (rc == 0)) {
		printf("addBiosEntry: line %u\n", lineNum);
		TSS_EVENT_Line_Trace(&event);
	    }
	    /* don't send no action events */
	    if (!endOfFile && (rc == 0)) {
		if (event.eventType == EV_NO_ACTION) {
		    continue;
		}
	    }
	    /* serialize the event into the json command */
	    if (!endOfFile && (rc == 0)) {
		rc = JS_Cmd_AddEvent12(command,
				       lineNum,
				       &event);
	    }
	}
	if (infile != NULL) {
	    fclose(infile);		/* @2 */
	}
    }		/* biosInputFilename not NULL */
    return rc;
}

#ifndef TPM_ACS_NOIMA

/* addImaEntry() adds the IMA events from the event log file 'imaInputFilename'.

   It is conditional on the server request json

   "imaevent1":"0000000aa97937766682b65c10a07c5c50363745f8e08b2700000007696d612d7369670000003a280000007368613235363a00078a025f29541d6c5f3d4232c9028d88b606a962114ed5471f091d9cc85acadb060000002f696e69740000000000",
*/
   
static uint32_t addImaEntry(json_object *command,
			    const char *imaInputFilename,
			    int		littleEndian,
			    const char *imaEntryString)	/* FIXME */
{
    uint32_t 	rc = 0;

    if (vverbose) printf("addImaEntry: Entry\n");
    int imaEntry;	/* response as an integer */
    if (rc == 0) {
	sscanf(imaEntryString, "%u", &imaEntry);
    }    
    if (rc == 0) {
	if (imaEntry >= 0) {
	    if (vverbose) printf("addImaEntry: start with imaEntry %d\n", imaEntry);
	}
	else {
	    if (vverbose) printf("addImaEntry: no IMA measurements required\n");
	    return 0;
	}
    }
    if (imaInputFilename != NULL) {
	/* open the IMA event log file */
	FILE *inFile = NULL;
	if (rc == 0) {
	    inFile = fopen(imaInputFilename,"rb");	/* closed @2 */
	    if (inFile == NULL) {
		printf("ERROR: addImaEntry: Unable to open event log file '%s'\n",
		       imaInputFilename);
		rc = ACE_FILE_OPEN;
	    }
	}
	ImaEvent 		imaEvent;
	int 			event;
	int 			endOfFile = FALSE;
	if (vverbose) printf("addImaEntry: skipping to event %u\n", imaEntry);
	for (event = 0 ; (rc == 0) && (event < imaEntry) && !endOfFile ; event++) {
	    if (rc == 0) {
		IMA_Event_Init(&imaEvent);
		rc = IMA_Event_ReadFile(&imaEvent,	/* freed by caller */
					&endOfFile,
					inFile,
					littleEndian);		/* little endian */
		IMA_Event_Free(&imaEvent);
	    }
	    /* the measurements to be skipped had better still be there */
	    if (rc == 0) {
		if (endOfFile) {
		    if (vverbose) printf("addImaEntry: end of file skiping entry %u\n",
					 event);
		    rc = ACE_FILE_READ;
		}
	    }	
	}
	/* read and send the rest of the events, until end of file */
	for ( ; (rc == 0) && !endOfFile; event++) {
	    if (rc == 0) {
		if (vverbose) printf("addImaEntry: reading event %u\n", event);
		IMA_Event_Init(&imaEvent);
		rc = IMA_Event_ReadFile(&imaEvent,	/* freed by caller */
					&endOfFile,
					inFile,
					littleEndian);		/* little endian */
	    }
	    if ((rc == 0) && !endOfFile) {
		if (vverbose) IMA_Event_Trace(&imaEvent, TRUE);
	    }
	    if ((rc == 0) && !endOfFile) {
		/* serialize and add this IMA event to the json command */
		if (vverbose) printf("addImaEntry: add entry %u\n", event);
		rc = JS_Cmd_AddImaEvent(command,
					&imaEvent,				     
					event);
	    }
	    IMA_Event_Free(&imaEvent);
	}
	if (inFile != NULL) {
	    fclose(inFile);		/* @2 */
	}
    }		/* imaInputFilename not NULL */
    return rc;
}

#endif	/* TPM_ACS_NOIMA */

/* runQuote() runs the TPM quote.  Loads a key under the parent at SRK_HANDLE.

   Returns the signature, quote data, and PCRs.

   The attestation key comes from files saved during enrollment.

   /// Retrieve TPM quote
   /// @param[out] pcrBank PCR values
   /// @param[out] TPM_CAP_VERSION_INFO versionInfo
   /// @param[out] signature Quote signature from TPM
   /// @param[out] boottimeString Boot time as a string
   /// @param[in] boottimeStringLen Maximum byte length of boottimeString 
   /// @param[in] nonceBin Nonce supplied by server
   /// @param[in] nonceLen Byte length of nonceBin
   /// @param[in] pcrSelection PCRs to retrieve
   /// @param[in] attestKey Attestation key
   /// @param[in] srkPassword Attestation public key parent password
   */

static TPM_RC runQuote12(TPM_PCR_INFO_SHORT 	*pcrData,
			 uint32_t 		*versionInfoSize,
			 TPM_CAP_VERSION_INFO 	*versionInfo,
			 uint32_t 		*signatureSize,
			 uint8_t 		*signature,
			 const unsigned char 	*nonceBin,
			 const TPM_PCR_SELECTION *pcrSelection,
			 TPM_KEY12 		*attestKey,	/* quote signing key */
			 const char 		*srkPassword)
{
    uint32_t 		rc = 0;
    TPM_RC 		rc1;
    TSS_CONTEXT		*tssContext = NULL;
    TPM_HANDLE 		keyHandle = 0;
    
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* create an OIAP session for general use */
    TPM_AUTHHANDLE sessionHandle = TPM_RH_NULL;
    if (rc == 0) {
	if (vverbose) printf("runQuote12: startOIAP\n");
	rc = startOIAP(tssContext, &sessionHandle);
    }
    
    /* load the quote signing key */
    if (rc == 0) {
	if (vverbose) printf("runQuote12: load attestation quote signing key\n");
	rc = loadObject12(tssContext, &keyHandle,
			  attestKey, sessionHandle, srkPassword);
    }
    /* sign the quote */
    if (rc == 0) {
	if (vverbose) printf("runQuote12: sign quote with key handle %08x\n", keyHandle);
	rc = signQuote12(tssContext,
			 pcrData,
			 versionInfoSize,
			 versionInfo,
			 signatureSize,
			 signature,
			 keyHandle,
			 nonceBin,
			 pcrSelection,
			 sessionHandle, NULL);	/* enpty AIK password */
    }   
    /* flush the quote signing key */
    if ((tssContext != NULL) && (keyHandle != 0)) {
	rc1 = flushSpecific(tssContext, keyHandle, TPM_RT_KEY);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* flush the OIAP session */
    if (sessionHandle != TPM_RH_NULL) {
	rc1 = flushSpecific(tssContext,
		      sessionHandle, TPM_RT_AUTH);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

/* getBootTime() reads the machine boot time from /proc/stat

   The line in the file is of the form:  btime nnnnn

   where n is a decimal string.

   boottimeMax is the maximum size of the supplied boottime array.
*/

uint32_t getBootTime(char *boottime,
		     size_t boottimeMax)
{
    uint32_t rc = 0;
    FILE *fp = NULL;

    if (rc == 0) {
	fp = fopen("/proc/stat", "r");		/* closed @1 */
	if (fp == NULL) {
	    printf("ERROR: getBootTime: /proc/stat open failed\n");
	    rc = 1;
	}
    }
    char line [128];
    char *p = NULL;	/* for fgets, then moves */
    if (rc == 0) {
	do {
	    /* read a line from /proc/stat */
	    p = fgets(line, sizeof(line), fp);
	    if (p != NULL) {
		if (strncmp(line, "btime", strlen("btime")) == 0) {
		    if (vverbose) printf("getBootTime: %s", line);
		    break;	/* if found the btime line, exit loop */
		}
	    }
	} while (p != NULL);	/* if no more lines, exit loop */
	/* if the btime line was not found in /proc/stat, return an error */
	if (p == NULL) {
	    printf("ERROR: getBootTime: btime not found\n");
	    rc = 1;
	}
    }
    char *pdec = NULL;	/* point to boot time decimal string */
    /* should be space between btime and decimal string */
    if (rc == 0) {
	p = strchr(line, (int)' ');
	if (p == NULL) {
	    printf("ERROR: getBootTime: parse error\n");
	    rc = 1;
	}
	else {
	    pdec = p+1;	/* skip past the space */
	}
    }
    char *pend = NULL;	/* point to newline, changed to nul */
    if (rc == 0) {
	pend = strchr(pdec, (int)'\n');
	/* remove trailing newline from decimal boot time */
	if (pend != NULL) {
	    *pend = '\0';
	}
	if (vverbose) printf("getBootTime: boottime string %s\n", pdec);
	time_t bootTimeBin;
	sscanf(pdec, "%lu", (unsigned long *)&bootTimeBin);
	if (vverbose) printf("getBootTime: boottime long: %lu\n", (unsigned long)bootTimeBin);
	struct tm *bootTimeTm = localtime(&bootTimeBin);
	strftime(boottime, boottimeMax, "%Y-%m-%d %H:%M:%S", bootTimeTm);
	if (vverbose) printf("getBootTime: %s\n", boottime);
    }
    if (fp != NULL) {
	fclose(fp);		/* @1 */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("client12\n");
    printf("\n");
    printf("Runs an attestation client sequence\n");
    printf("\tget nonce\n");
    printf("\tsend quote\n");
    printf("\tsend BIOS measurement list\n");
    printf("\tsend IMA measurement list\n");
    printf("\n");
    printf("[-ifb BIOS filename (binary measurement log)]\n");
    printf("\tdefault sends empty log\n");
#ifndef TPM_ACS_NOIMA
    printf("-ifi IMA filename (binary measurement log)\n");
#endif
    printf("[-ho ACS server host name (default localhost)]\n");
    printf("[-po ACS server port (default ACS_PORT or 2323)]\n");
    printf("[-ma client machine name (default host name)]\n");
    printf("[-pwds SRK password (default zeros)]\n");
    printf("[-bf boottime file name including newline (default use /proc/stat]\n");
    printf("\tdate +\"%%F %%T\" >! bootfile can be used to create the file\n");
    printf("\n");
    printf("\tFor debug only\n");
    printf("\n");
    printf("[-co connection only]\n");
    printf("[-no nonce only]\n");
    printf("[-qo quote only]\n");
    printf("[-bq create bad quote]\n");
    printf("[-bt make random boot time (to defeat incremental event log)\n");
    printf("[-p pass count (default 1)]\n");
    printf("[-v verbose trace]\n");
    printf("[-vv very verbose trace]\n");
    printf("\n");
    exit(1);	
}
