/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client    				*/
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
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscryptoh.h>

#include "objecttemplates.h"
#include "cryptoutils.h"

#ifndef TPM_ACS_NOIMA
#include "imalib.h"
#endif

#include "config.h"
#include "commonerror.h"
#include "clientjson.h"
#include "commonjson.h"
#include "clientsocket.h"
#include "eventlib.h"
#include "commonutils.h"
#include "commontss.h"
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
static uint32_t createQuote(json_object **quoteResponseJson,
			    const char *akpubFilename,
			    const char *akprivFilename,
			    const char *hostname,
			    short port,
			    const char *machineName,
			    const char *nonceString,
			    const TPML_PCR_SELECTION *pcrSelection,
			    const char *biosInputFilename,
			    const char *biosEntryString,
			    const char *imaInputFilename,
			    int 	littleEndian,
			    TPMI_ALG_HASH  templateHashAlgId,
			    const char *imaEntryString);
static uint32_t addBiosEntry(json_object *command,
			     const char *biosInputFilename,
			     const char *biosEntryString);
#ifndef TPM_ACS_NOIMA
static uint32_t addImaEntry(json_object *command,
			    const char *imaInputFilename,
			    int		littleEndian,
			    TPMI_ALG_HASH  templateHashAlgId,
			    const char *imaEntryString);
#endif

int vverbose = 0;
int verbose = 0;

/* PVM supports an attestation client for the POWER VM */

#ifdef TPM_ACS_PVM_REMOTE
const char* g_sphost = NULL; /* Service processor hostname */
const char* g_spport = NULL; /* Attestation port on service processor */
#endif

int main(int argc, char *argv[])
{
    int rc = 0;
    int	i;    		/* argc iterator */

    /* command line argument defaults */
    const char *boottimeFileName = NULL;
    char boottimeString[128];
    const char *biosInputFilename = NULL;

#if defined(TPM_ACS_PVM_REMOTE) || defined(TPM_ACS_PVM_INBAND)
    char  logfilename[100];
#endif
    const char *imaInputFilename = NULL;
    int 	littleEndian = TRUE;
    int		type = 1;			/* IMA log type, default 1 */
    TPMI_ALG_HASH templateHashAlgId = TPM_ALG_SHA1;	/* default algorithm for event log */
    const char *hostname = "localhost";		/* default server */
    const char 	*portString = NULL;		/* server port */
    short port = 2323;				/* default server */
    const char *machineName = NULL;		/* default use gethostname() */
    const char *akpubFilename = AK_RSA_PUB_FILENAME;	/* default RSA */
    const char *akprivFilename = AK_RSA_PRIV_FILENAME;	/* default RSA */
    char    	akpubFullName[256];		/* approx 168 for directory, 64 for machine name, 23
						   for file name */
    char    	akprivFullName[256];

    unsigned int passes = 1;			/* pass counter, for debug */
    unsigned int passNumber;
    int		connectionOnly = 0;		/* for server debug */
    int		nonceOnly = 0;			/* for server debug */
    int		quoteOnly = 0;			/* for server debug */
    int		badQuote = 0;			/* for server debug */
    int		makeBootTime = 0;		/* to defeat incremental event log */

    /* the optional demo is currently IBM internal only */
    int		optionalDemo = 0;		/* optional demo */
    int		optionalDemoOnly = 0;		/* optional demo */

    optionalDemo = optionalDemo;
    optionalDemoOnly = optionalDemoOnly;
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
	if (strcmp(argv[i],"-alg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    akpubFilename = AK_RSA_PUB_FILENAME;
		    akprivFilename = AK_RSA_PRIV_FILENAME;
		}
		else if (strcmp(argv[i],"ec") == 0) {
		    akpubFilename = AK_EC_PUB_FILENAME;
		    akprivFilename = AK_EC_PRIV_FILENAME;
		}
		else {
		    printf("Bad parameter for -alg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-alg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ty") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &type);
		switch (type) {
		  case 1:				/* original sha1 event log */
		  case 2:				/* sha1 zero extended event log */
		    templateHashAlgId = TPM_ALG_SHA1;
		    break;
		  case 3:
		    templateHashAlgId = TPM_ALG_SHA256;
		    break;				/* sha256 event log */
		  default:
		    printf("Bad parameter %s for -ty\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-ty option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ho") == 0) {
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
#if !defined(TPM_ACS_PVM_REMOTE) && !defined(TPM_ACS_PVM_INBAND)
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
#endif
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
#ifdef TPM_ACS_PVM_REMOTE
	else if (strcmp(argv[i], "-sphost") == 0) {
	    i++;
	    if (i < argc) {
		g_sphost = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -sphost\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-spport") == 0) {
	    i++;
	    if (i < argc) {
		g_spport = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -spport\n");
		printUsage();
	    }
	}
#endif
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
    /* shared with enroll */
    rc = makeAkFilenames(akpubFullName,
			 akprivFullName,
			 sizeof(akprivFullName),
			 akpubFilename,
			 akprivFilename,
			 machineName);
    if (rc != 0) {
	exit(1);
    }
#ifdef TPM_ACS_PVM_REMOTE
    if (NULL == g_sphost) {
        printf("\nERROR: Missing -sphost\n");
        printUsage();
    }
#endif
#if defined(TPM_ACS_PVM_REMOTE) || defined(TPM_ACS_PVM_INBAND)
    /* clientPvmLocal.c retrieveTPMLog() makes an hcall to retrieve the contents of the TPM log and
       stores the contents in the temp file that was passed.  This generates a unique temporary
       filename in /tmp/ to be filled in with the log contents from the hcall.  The file descriptor
       returned (f) is closed and not used again */
    strcpy(logfilename,"/tmp/tpmlogXXXXXX");
    int f = mkstemp(logfilename);
    if (f < 0) {
        printf("\nERROR: Unable to create temporary logfile\n");
        exit(1);
    }
    close(f);
    if (vverbose) printf("Using temporary logfile : %s\n", logfilename);
    biosInputFilename = logfilename;
#endif
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
	if (!connectionOnly && !quoteOnly && !optionalDemoOnly) {
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
	if ((rc == 0) && quoteOnly) {
	    rc = loadNonce(&nonceStringSaved,		/* freed @4 */
			   &pcrSelectStringSaved);	/* freed @5 */
	    nonceString = nonceStringSaved;
	    pcrSelectString = pcrSelectStringSaved;
	}
	json_object *quoteResponseJson = NULL;		/* @2 */
	TPML_PCR_SELECTION pcrSelection;
	if ((rc == 0) &&
	    !connectionOnly && !nonceOnly && !optionalDemoOnly) {

	    rc = Structure_Scan(&pcrSelection,
				(UnmarshalFunction_t)TSS_TPML_PCR_SELECTION_Unmarshalu,
				pcrSelectString);
	}
	if ((rc == 0) && !connectionOnly && !nonceOnly && !optionalDemoOnly) {

	    rc = createQuote(&quoteResponseJson,	/* freed @2 */
			     akpubFullName, akprivFullName,
			     hostname, port,
			     machineName,
			     nonceString, &pcrSelection,
			     biosInputFilename, biosEntryString,
			     imaInputFilename, littleEndian, templateHashAlgId, imaEntryString);
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
#ifndef TPM_ACS_NOIMA
#endif
#if defined(TPM_ACS_PVM_REMOTE) || defined(TPM_ACS_PVM_INBAND)
	unlink(logfilename);
#endif
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
   "command":"nonce",
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
			  "nonce",			/* command */
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
    /* check that response is nonce */
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

/* createQuote() runs a TPM quote, and sends the quote command to the server.

   "command":"quote",
   "hostname":"cainl.watson.ibm.com",
   "quoted":"hexascii",
   "signature":"hexascii",
   }
   {
   "response":"quote"
*/

static uint32_t createQuote(json_object **quoteResponseJson,	/* freed by caller */
			    const char *akpubFilename,
			    const char *akprivFilename,
			    const char *hostname,
			    short port,
			    const char *machineName,
			    const char *nonceString,
			    const TPML_PCR_SELECTION *pcrSelection,
			    const char *biosInputFilename,
			    const char *biosEntryString,
			    const char *imaInputFilename,
			    int 	littleEndian,
			    TPMI_ALG_HASH  templateHashAlgId,
			    const char *imaEntryString)
{
    uint32_t 	rc = 0;
    if (verbose) printf("INFO: createQuote\n");
    if (vverbose) printf("createQuote: nonce %s\n", nonceString);
    if (vverbose) printf("createQuote: biosEntryString %s\n", biosEntryString);
    if (vverbose) printf("createQuote: biosInputFilename %s\n", biosInputFilename);

    /* convert nonce to binary and use as qualifyingData */
    unsigned char *nonceBin = NULL;
    size_t nonceLen;
    if (rc == 0) {
	rc = Array_Scan(&nonceBin,		/* freed @1 */
			&nonceLen,
			nonceString);
    }
    TPM2B_PRIVATE akPriv;	/* quote signing key */
    TPM2B_PUBLIC akPub;
    if (rc == 0) {
	rc = TSS_File_ReadStructureFlag(&akPub,
					(UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
					TRUE,
					akpubFilename);
    }
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&akPriv,
				    (UnmarshalFunction_t)TSS_TPM2B_PRIVATE_Unmarshalu,
				    akprivFilename);
    }
    /* run the TPM_Quote using the supplied nonce and pcrSelect.

       Returns the quoted that was signed and the quote signature. */
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;
    if (rc == 0) {
	rc = runQuote(&quoted,
		      &signature,
		      nonceBin, nonceLen,
		      pcrSelection,
		      &akPriv,		/* quote signing key */
		      &akPub);
    }
    /* quoted array to string */
    char *quotedString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&quotedString,		/* freed @2 */
			       quoted.t.attestationData,
			       quoted.t.size);
    }
    /* attestation signature to string */
    uint16_t written;
    uint8_t *signatureBin = NULL;
    if (rc == 0) {
	rc = TSS_Structure_Marshal(&signatureBin,	/* freed @3 */
				   &written,
				   &signature,
				   (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu);
    }
    char *signatureString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&signatureString,	/* freed @4 */
			       signatureBin,
			       written);
    }
    /*
      Construct the Quote client to server command
    */
    json_object *command = NULL;
    if (rc == 0) {
	rc = JS_Cmd_NewQuote(&command,			/* freed @1 */
			     machineName,
			     quotedString,
			     signatureString);
    }
    /* add the BIOS event log to the response if requested */
    if (rc == 0) {
	rc = addBiosEntry(command, biosInputFilename, biosEntryString);
    }
#ifndef TPM_ACS_NOIMA
    /* adds the IMA events from the event log file 'imaInputFilename' */
    if (rc == 0) {
	rc = addImaEntry(command, imaInputFilename, littleEndian, templateHashAlgId, imaEntryString);
    }
#endif
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
	rc = Socket_Process(&rspBuffer, &rspLength,	/* freed @6 */
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
	if (verbose) JS_ObjectTrace("INFO: createQuote: response", *quoteResponseJson);
    }
    /* check that response is quote */
    if (rc == 0) {
	rc = JS_Rsp_Quote(*quoteResponseJson);
    }
    free(nonceBin);		/* @1 */
    free(quotedString);		/* @2 */
    free(signatureBin);		/* @3 */
    free(signatureString);	/* @4 */
    free(cmdBuffer);		/* @5 */
    free(rspBuffer);		/* @6 */
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
	/* place the event log in a file if it is not already there */
	if (rc == 0) {
	    rc = retrieveTPMLog(biosInputFilename);
	}
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
	TCG_PCR_EVENT2 		event2;		/* hash agile TPM 2.0 events */
	TCG_PCR_EVENT 		event;		/* TPM 1.2 format header event */
	int 			endOfFile = FALSE;
	/* the first event is a TPM 1.2 format event */
	/* NOTE This informational event can be sent to the server to describe digest algorithms,
	   event log version, etc. */
	/* read a TCG_PCR_EVENT event line */
	if (rc == 0) {
	    rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
	}
	/* trace the measurement log line */
	if (verbose && !endOfFile && (rc == 0)) {
	    if (vverbose) printf("addBiosEntry: line 0\n");
	    if (vverbose) TSS_EVENT_Line_Trace(&event);
	}
	/* parse the event */
	TCG_EfiSpecIDEvent specIdEvent;
	if (verbose && !endOfFile && (rc == 0)) {
	    rc = TSS_SpecIdEvent_Unmarshal(&specIdEvent,
					   event.eventDataSize, event.event);
	}
	/* trace the event in the first line */
	if (verbose && !endOfFile && (rc == 0)) {
	    if (vverbose) TSS_SpecIdEvent_Trace(&specIdEvent);
	}
	/* serialize the event into the json command */
	if (!endOfFile && (rc == 0)) {
	    rc = JS_Cmd_AddEvent0(command,
				  0,
				  &event);
	}
	/* scan each measurement 'line' in the binary */
	unsigned int 		lineNum;	/* FIXME no incremental log yet */
	for (lineNum = 1 ; !endOfFile && (rc == 0) ; lineNum++) {
	    /* read a TCG_PCR_EVENT2 event line */
	    if (rc == 0) {
		rc = TSS_EVENT2_Line_Read(&event2, &endOfFile, infile);
	    }
	    /* debug tracing */
	    if (vverbose && !endOfFile && (rc == 0)) {
		printf("addBiosEntry: line %u\n", lineNum);
		TSS_EVENT2_Line_Trace(&event2);
	    }
	    /* serialize the event into the json command */
	    if (!endOfFile && (rc == 0)) {
		rc = JS_Cmd_AddEvent(command,
				     lineNum,
				     &event2);
	    }
	}
	if (infile != NULL) {
	    fclose(infile);		/* @2 */
	}
    }		/* biosInputFilename not NULL */
    return rc;
}

/* addImaEntry() adds the IMA events from the event log file 'imaInputFilename'.

   It is conditional on the server request json

   "imaevent1":"0000000aa97937766682b65c10a07c5c50363745f8e08b2700000007696d612d7369670000003a280000007368613235363a00078a025f29541d6c5f3d4232c9028d88b606a962114ed5471f091d9cc85acadb060000002f696e69740000000000",
*/
 
#ifndef TPM_ACS_NOIMA
static uint32_t addImaEntry(json_object *command,
			    const char *imaInputFilename,
			    int		littleEndian,
			    TPMI_ALG_HASH templateHashAlgId,
			    const char *imaEntryString)	/* FIXME */
{
    uint32_t 	rc = 0;

    if (vverbose) printf("addImaEntry: Entry\n");
    int imaEntry;	/* response as an integer */

    if (rc == 0) {
	rc = JS_Cmd_AddImaDigestAlgorithm(command,
					  templateHashAlgId);
    }
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
	/* place the event log in a file if it is not already there */
	if (rc == 0) {
	    rc = retrieveTPMLog(imaInputFilename);
	}
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
	ImaEvent2 		imaEvent;
	int 			event;
	int 			endOfFile = FALSE;
	if (vverbose) printf("addImaEntry: skipping to event %u\n", imaEntry);
	for (event = 0 ; (rc == 0) && (event < imaEntry) && !endOfFile ; event++) {
	    if (rc == 0) {
		IMA_Event2_Init(&imaEvent);
		rc = IMA_Event2_ReadFile(&imaEvent,	/* freed by caller */
					 &endOfFile,
					 inFile,
					 littleEndian,		/* little endian */
					 templateHashAlgId);
		IMA_Event2_Free(&imaEvent);
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
#if 0
	/* if not end of file, have more measurements to send */
	/* add number of first ima entry */
	if ((rc == 0) && !endOfFile) {
	    rc = JS_Cmd_AddImaEntry(command,
				    imaEntryString);
	}
#endif
	/* read and send the rest of the events, until end of file */
	for ( ; (rc == 0) && !endOfFile; event++) {
	    if (rc == 0) {
		if (vverbose) printf("addImaEntry: reading event %u\n", event);
		IMA_Event2_Init(&imaEvent);
		rc = IMA_Event2_ReadFile(&imaEvent,	/* freed by caller */
					 &endOfFile,
					 inFile,
					 littleEndian,		/* little endian */
					 templateHashAlgId);

	    }
	    if ((rc == 0) && !endOfFile) {
		if (vverbose) IMA_Event2_Trace(&imaEvent, TRUE);
	    }
	    if ((rc == 0) && !endOfFile) {
		/* serialize and add this IMA event to the json command */
		if (vverbose) printf("addImaEntry: add entry %u\n", event);
		rc = JS_Cmd_AddImaEvent(command,
					&imaEvent,
					event);
	    }
	    IMA_Event2_Free(&imaEvent);
	}
	if (inFile != NULL) {
	    fclose(inFile);		/* @2 */
	}
    }		/* imaInputFilename not NULL */
    return rc;
}
#endif


static void printUsage(void)
{
    printf("\n");
#ifdef TPM_ACS_PVM_REMOTE
    printf("acsPvmRemoteClient\n");
#elif defined(TPM_ACS_PVM_INBAND)
    printf("acsPvmClient\n");
#else
    printf("client\n");
#endif
    printf("\n");
    printf("Runs an attestation client sequence\n");
    printf("\tget nonce\n");
    printf("\tsend quote\n");
    printf("\tsend BIOS measurement list\n");
    printf("\tsend IMA measurement list\n");
    printf("\n");
    printf("[-alg (rsa or ec) (default rsa)]\n");
#if !defined(TPM_ACS_PVM_REMOTE) && !defined(TPM_ACS_PVM_INBAND)
    printf("[-ifb BIOS filename (binary measurement log)]\n");
    printf("\tdefault sends empty log\n");
#endif
#ifndef TPM_ACS_NOIMA
    printf("-ifi IMA filename (binary measurement log)\n");
    printf("[-be\tIMA file is big endian (default little endian)]\n");
#endif
    printf("[-ho ACS server host name (default localhost)]\n");
    printf("[-po ACS server port (default ACS_PORT or 2323)]\n");
    printf("[-ma client machine name (default host name)]\n");
    printf("[-bf boottime file name including newline (default use /proc/stat]\n");
    printf("\tdate +\"%%F %%T\" >! bootfile can be used to create the file\n");

    // date +"%F %T"

#ifdef TPM_ACS_PVM_REMOTE
    printf("[-sphost System service processor hostname]\n");
    printf("[-spport System service processor attestation port (default 30015)]\n");
#endif
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

