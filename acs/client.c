/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: client.c 1167 2018-04-18 18:38:04Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017					*/
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

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssfile.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssprint.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsscryptoh.h>

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
			 const char **nonceString,
			 const char **pcrSelectString);
static uint32_t createQuote(json_object **quoteResponseJson,
			    const char *akpubFilename,
			    const char *akprivFilename,
			    const char *hostname,
			    short port,
			    const char *machineName,
			    char *boottimeString,
			    size_t boottimeStringLen,
			    const char *nonceString,
			    const TPML_PCR_SELECTION *pcrSelection);
static uint32_t sendBiosMeasurements(json_object **biosEntryResponseJson,
				     const char *hostname,
				     short port,
				     const char *machineName,
				     const char *nonce,
				     const char *biosInputFilename,
				     const char *biosEntryString,
				     const char **imaEntryString);
static uint32_t parseQuoteResponse(const char **biosEntryString,
				   const char **imaEntryString,
				   json_object *quoteResponseJson);
#ifndef TPM_ACS_NOIMA
static uint32_t sendImaMeasurements(json_object **imaEntryResponseJson,
				    const char *hostname,
				    short port,
				    const char *machineName,
				    const char *nonceString,
				    const char *imaInputFilename,
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
#ifndef TPM_ACS_NOIMA
    const char *imaInputFilename = NULL;
#endif
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
    int		biosEntryOnly = 0;		/* for server debug */
    int		imaEntryOnly = 0;		/* for server debug */
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
	else if (strcmp(argv[i],"-bo") == 0) {
	    biosEntryOnly = 1;
	}
	else if (strcmp(argv[i],"-io") == 0) {
	    imaEntryOnly = 1;
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
    clock_t biosEventsStart;
    clock_t biosEventsEnd;
    double biosEventsDiff = 0;
    clock_t imaEventsStart;
    clock_t imaEventsEnd;
    double imaEventsDiff = 0;
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
	    unsigned char boottimeBin[32];
	    /* generate binary random value */
	    int irc = RAND_bytes(boottimeBin, sizeof(boottimeBin));
	    /* convert to boottimeBintext for the response */
	    Array_Print(boottimeString, NULL, FALSE,
			boottimeBin, sizeof(boottimeBin));
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
	TPML_PCR_SELECTION pcrSelection;

	/* get the quote nonce and pcr selection from the response */
	nonceStart = time(NULL);
	if ((rc == 0) &&
	    !connectionOnly && !quoteOnly && !biosEntryOnly && !imaEntryOnly && !optionalDemoOnly) {

	    rc = getNonce(&nonceResponseJson,	/* freed @1 */
			  hostname, port,
			  machineName,
			  &nonceString, &pcrSelectString);
	}
	nonceEnd = time(NULL);

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
	if ((rc == 0) && (quoteOnly || biosEntryOnly || imaEntryOnly)) {
	    rc = loadNonce(&nonceStringSaved,		/* freed @4 */
			   &pcrSelectStringSaved);	/* freed @5 */
	    nonceString = nonceStringSaved;
	    pcrSelectString = pcrSelectStringSaved;
	}
	json_object *quoteResponseJson = NULL;		/* @2 */
	if ((rc == 0) &&
	    !connectionOnly && !nonceOnly && !biosEntryOnly && !imaEntryOnly && !optionalDemoOnly) {

	    rc = Structure_Scan(&pcrSelection,
				(UnmarshalFunction_t)TPML_PCR_SELECTION_Unmarshal,
				pcrSelectString);
	}
	if ((rc == 0) && !connectionOnly && !nonceOnly &&
	    !biosEntryOnly && !imaEntryOnly && !optionalDemoOnly) {

	    rc = createQuote(&quoteResponseJson,	/* freed @2 */
			     akpubFullName, akprivFullName,
			     hostname, port,
			     machineName,
			     boottimeString, sizeof(boottimeString),
			     nonceString, &pcrSelection);
	}
	quoteEnd = time(NULL);
	
	/* determine if the server quote response asked for BIOS log, IMA log, or neither */
	const char *biosEntryString = NULL;
	const char *imaEntryString = NULL;
	if ((rc == 0) &&
	    !connectionOnly && !nonceOnly && !quoteOnly && !biosEntryOnly && !imaEntryOnly && !optionalDemoOnly) {

	    rc = parseQuoteResponse(&biosEntryString,
				    &imaEntryString,
				    quoteResponseJson);
	}
	if ((rc == 0) && (biosEntryOnly || imaEntryOnly)) {
	    biosEntryString = "0";	/* simulate quote response */
	    imaEntryString = "0"; 
	}
	/* send the BIOS event log measurements */
	biosEventsStart = time(NULL);
	json_object *biosEntryResponseJson = NULL;		/* @3 */
	    if ((rc == 0) &&
		!connectionOnly && !nonceOnly && !quoteOnly && !imaEntryOnly && !optionalDemoOnly) {

		rc = sendBiosMeasurements(&biosEntryResponseJson,	/* freed @3 */
					  hostname, port,
					  machineName,
					  nonceString, 
					  biosInputFilename,
					  biosEntryString,
					  &imaEntryString);
	}
	biosEventsEnd = time(NULL);
#ifndef TPM_ACS_NOIMA
	imaEventsStart = time(NULL);
	json_object *imaEntryResponseJson = NULL;		/* @6 */
	if ((rc == 0) &&
	    !connectionOnly && !nonceOnly && !quoteOnly && !biosEntryOnly && !optionalDemoOnly &&
	    (imaInputFilename != NULL)) {

	    rc = sendImaMeasurements(&imaEntryResponseJson,	/* freed @6 */
				     hostname, port,
				     machineName,
				     nonceString, 
				     imaInputFilename,
				     imaEntryString);
	}
	imaEventsEnd = time(NULL);
#endif
	if ((rc == 0) && connectionOnly) {
	    int sock_fd = -1;		/* error value, for close noop */
	    if (rc == 0) {
		rc = Socket_Open(&sock_fd, hostname, port);
	    }
	    Socket_Close(sock_fd);
	}
	JS_ObjectFree(nonceResponseJson);	/* @1 */
	JS_ObjectFree(quoteResponseJson);	/* @2 */
	JS_ObjectFree(biosEntryResponseJson);	/* @3 */
	free(nonceStringSaved);			/* @4 */
	free(pcrSelectStringSaved);		/* @5 */
#ifndef TPM_ACS_NOIMA
	JS_ObjectFree(imaEntryResponseJson);	/* @6 */
#endif
#if defined(TPM_ACS_PVM_REMOTE) || defined(TPM_ACS_PVM_INBAND)
	unlink(logfilename);
#endif
	if (passes > 1) {
	    printf("End pass %u\n", passNumber+1);
	}
	nonceDiff += difftime(nonceEnd, nonceStart);
	quoteDiff += difftime(quoteEnd, quoteStart);
	biosEventsDiff += difftime(biosEventsEnd , biosEventsStart);
	imaEventsDiff += difftime(imaEventsEnd, imaEventsStart);
	totalEnd = time(NULL);
	totalDiff += difftime(totalEnd, totalStart);
    }	/* end pass count */

    if (passes > 1) {
	printf("\n");
	printf("Nonce time \t\t%f\n", nonceDiff);
	printf("Quote time \t\t%f\n", quoteDiff);
	printf("BiosEvents time \t%f\n", biosEventsDiff);
	printf("ImaEvents time \t\t%f\n", imaEventsDiff);
	printf("Total time \t\t%f\n", totalDiff);
	printf("\n");
	printf("Nonce time per pass \t\t%f\n", nonceDiff / passes);
	printf("Quote time per pass \t\t%f\n", quoteDiff / passes);
	printf("biosEvents time per pass \t%f\n", biosEventsDiff / passes);
	printf("ImaEvents time per pass \t%f\n", imaEventsDiff / passes);
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
   }

   The server response is of the form:
   
   {
   "response":"nonce",
   "nonce":"5ef7c0cf2bc1909d27d1acf793a5fd252be7bd29aca6ea191a4f40a60f814b00",
   "pcrselect":"00000002000b03ff0000000403000400"
   }
*/

static uint32_t getNonce(json_object **nonceResponseJson,	/* freed by caller */
			 const char *hostname,
			 short port,
			 const char *machineName,
			 const char **nonceString,
			 const char **pcrSelectString)
{
    uint32_t 	rc = 0;
    uint32_t 	cmdLength;
    uint8_t 	*cmdBuffer = NULL;
    uint32_t 	rspLength;
    uint8_t 	*rspBuffer = NULL;
    
    if (verbose) printf("INFO: getNonce\n");
    /* construct the get nonce command packet */
    if (rc == 0) {
	rc = JS_Cmd_Nonce(&cmdLength,
			  (char **)&cmdBuffer,		/* freed @1 */
			  "nonce",			/* command */
			  machineName);
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
	rc = JS_Rsp_Nonce(nonceString, pcrSelectString,
			  *nonceResponseJson);
    }
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
    return rc;
}

/* createQuote() runs a TPM quote, and sends the quote command to the server.  

   "command":"quote",
   "hostname":"cainl.watson.ibm.com",
   "boottime":"2016-03-21 09:08:25"
   "pcrnshan":"06e15db2520f67294627681175d58a5cfff7a475ca8a39f60ad29aacbac596c6",
   "quoted":"hexascii",
   "signature":"hexascii",
   }
   {
   "response":"quote"

   and optionally
   
   "biosentry":"0"

   or
   
   "imaentry":"0"	or incremental
   }

*/

static uint32_t createQuote(json_object **quoteResponseJson,	/* freed by caller */
			    const char *akpubFilename,
			    const char *akprivFilename,
			    const char *hostname,
			    short port,
			    const char *machineName,
			    char *boottimeString,
			    size_t boottimeStringLen,
			    const char *nonceString,
			    const TPML_PCR_SELECTION *pcrSelection)
{
    uint32_t 	rc = 0;
    if (verbose) printf("INFO: createQuote\n");
    if (vverbose) printf("createQuote: nonce %s\n", nonceString);

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
	rc = TSS_File_ReadStructure(&akPub,
				    (UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
				    akpubFilename);
    }
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&akPriv,
				    (UnmarshalFunction_t)TPM2B_PRIVATE_Unmarshal,
				    akprivFilename);
    }
    /* run the TPM_Quote using the supplied nonce and pcrSelect.

       Returns the pcr array, a copy of the nonce (which should be the same as the input), the
       quoted that was signed (for debugging, since the server will not trust it) and the quote
       signature. */
    TPML_PCR_BANKS pcrBanks;
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;
    if (rc == 0) {
	rc = runQuote(&pcrBanks,
		      &quoted,
		      &signature,
		      boottimeString, boottimeStringLen,
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
				   (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal);
    }
    char *signatureString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&signatureString,	/* freed @4 */
			       signatureBin,
			       written);
    }
    /* convert all PCRs from binary to text, use the bank count and hash algorithm, but ignore the
       bit mask */
    char pcrSha1String[IMPLEMENTATION_PCR][(SHA1_DIGEST_SIZE * 2) + 1];
    char pcrSha256String[IMPLEMENTATION_PCR][(SHA256_DIGEST_SIZE * 2) + 1];
    uint32_t	bank;			/* iterate through PCR banks */
    uint32_t	pcrNum;			/* iterate through PCRs */

    /* iterate through PCR */
    for (pcrNum = 0 ; (rc == 0) && (pcrNum < IMPLEMENTATION_PCR) ; pcrNum++) {
	/* iterate through each bank */
	for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {

	    if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA256) {
		/* convert binary to text */
		Array_Print(pcrSha256String[pcrNum], NULL, FALSE,
			    pcrBanks.pcrBank[bank].digests[pcrNum].t.buffer, 
			    pcrBanks.pcrBank[bank].digests[pcrNum].t.size);
	    }
	    else if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA1) {
		/* convert binary to text */
		Array_Print(pcrSha1String[pcrNum], NULL, FALSE,
			    pcrBanks.pcrBank[bank].digests[pcrNum].t.buffer, 
			    pcrBanks.pcrBank[bank].digests[pcrNum].t.size);
	    }
	    else {
		printf("ERROR: createQuote: does not support algorithm %04x yet\n",
		       pcrSelection->pcrSelections[bank].hash);
		rc = 1;
	    }
	}
    }
    /*
      Construct the Quote client to server command
    */
    uint32_t cmdLength;
    uint8_t *cmdBuffer = NULL;
    uint32_t rspLength;
    uint8_t *rspBuffer = NULL;
    if (rc == 0) {
	rc = JS_Cmd_Quote(&cmdLength,(char **)&cmdBuffer,		/* freed @5 */
			  machineName,
			  boottimeString,
			  pcrSha1String,
			  pcrSha256String,
			  quotedString,
			  signatureString);
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

/* parseQuoteResponse() parses the quote respoonse and determines whether a BIOS log, an IMA log, or
   neither is requested.
*/

static uint32_t parseQuoteResponse(const char **biosEntryString,
				   const char **imaEntryString,
				   json_object *quoteResponseJson)
{
    uint32_t 	rc = 0;

    if (vverbose) printf("INFO: parseQuoteResponse\n");
    if (rc == 0) {
	rc = JS_ObjectGetString(biosEntryString, "biosentry", quoteResponseJson);
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(imaEntryString, "imaentry", quoteResponseJson);
    }
    return rc;
}
 
/* sendBiosMeasurements() sends BIOS events from the event log file 'biosInputFilename'.

   If no BIOS measurements are required, imaEntryString has already been set by the caller.  If BIOS
   measurements are required, imaEntryString is set here by the response.

   {
   "command":"biosentry",
   "hostname":"cainl.watson.ibm.com",
   "nonce":"1298d83cdd8c50adb58648d051b1a596b66698758b8d0605013329d0b45ded0c",
   "event1":"hexascii",
   }
   {
   "response":"biosentry"
   "imaentry":"00000000"
   }

*/

static uint32_t sendBiosMeasurements(json_object **biosEntryResponseJson, /* freed by caller */
				     const char *hostname,
				     short port,
				     const char *machineName,
				     const char *nonce,
				     const char *biosInputFilename,
				     const char *biosEntryString,
				     const char **imaEntryString)
{
    uint32_t 	rc = 0;
    
    if (vverbose) printf("sendBiosMeasurements: Entry\n");
    int biosEntry;	/* response as an integer */
    if (rc == 0) {
	sscanf(biosEntryString, "%u", &biosEntry);
    }    
    if (rc == 0) {
	if (biosEntry >= 0) {
	    if (vverbose) printf("sendBiosMeasurements: start with biosEntry %d\n", biosEntry);
	}
	else {
	    if (vverbose) printf("sendBiosMeasurements: no BIOS measurements required\n");
	    return 0;
	}
    }
    json_object *command = NULL;
    /* The client sends its boot time to the server. */
    /* add command and client hostname */
    if (rc == 0) {
	rc = JS_Cmd_NewBiosEntry(&command,
				 "biosentry",
				 machineName,
				 nonce);
    }
    if (biosInputFilename != NULL) {
	/* create the BIOS entry command json */
    
	/* place the event log in a file if it is not already there */
	if (rc == 0) {
	    rc = retrieveTPMLog(biosInputFilename);
	}
	/* open the BIOS event log file */
	FILE *infile = NULL;
	if (rc == 0) {
	    infile = fopen(biosInputFilename,"rb");	/* closed @2 */
	    if (infile == NULL) {
		printf("ERROR: sendBiosMeasurements: Unable to open event log file '%s'\n",
		       biosInputFilename);
		rc = 1;
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
	    if (vverbose) printf("sendBiosMeasurements: line 0\n");
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
	/* scan each measurement 'line' in the binary */
	unsigned int 		lineNum;	/* FIXME no incremental log yet */
	for (lineNum = 1 ; !endOfFile && (rc == 0) ; lineNum++) {
	    /* read a TCG_PCR_EVENT2 event line */
	    if (rc == 0) {
		rc = TSS_EVENT2_Line_Read(&event2, &endOfFile, infile);
	    }
	    /* debug tracing */
	    if (vverbose && !endOfFile && (rc == 0)) {
		printf("sendBiosMeasurements: line %u\n", lineNum);
		TSS_EVENT2_Line_Trace(&event2);
	    }
	    /* don't send no action events */
	    if (!endOfFile && (rc == 0)) {
		if (event2.eventType == EV_NO_ACTION) {
		    continue;
		}
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
	rc = Socket_Process(&rspBuffer, &rspLength,	/* freed @4 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(biosEntryResponseJson,		/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: sendBiosMeasurements: response", *biosEntryResponseJson);
    }
#ifndef TPM_ACS_NOIMA
    if (rc == 0) {
	rc = JS_Rsp_Bios(imaEntryString,
			 *biosEntryResponseJson);
    }
#else
    imaEntryString = imaEntryString;
#endif
    free(cmdBuffer);		/* @3 */
    free(rspBuffer);		/* @4 */
    return rc;
}

/*
  {
  "command":"imasentry",
  "hostname":"cainl.watson.ibm.com",
  "nonce":"1298d83cdd8c50adb58648d051b1a596b66698758b8d0605013329d0b45ded0c",
  "imaentry":"0",
  "event0":"hexascii",
  }
  {
  "response":"imaentry"
  }
*/

#ifndef TPM_ACS_NOIMA

static uint32_t sendImaMeasurements(json_object **imaEntryResponseJson,
				    const char *hostname,
				    short port,
				    const char *machineName,
				    const char *nonceString,
				    const char *imaInputFilename,
				    const char *imaEntryString)
{
    uint32_t rc = 0;
    if (vverbose) printf("sendImaMeasurements: Entry\n");

    int imaEntry;	/* response as an integer */
    if (rc == 0) {
	sscanf(imaEntryString, "%u", &imaEntry);
    }    
    if (rc == 0) {
	if (imaEntry >= 0) {
	    if (vverbose) printf("sendImaMeasurements: start with imaEntry %d\n", imaEntry);
	}
	else {
	    if (vverbose) printf("sendImaMeasurements: no measurements required\n");
	    return 0;
	}
    }
    json_object *command = NULL;
    /* add command and client hostname */
    if (rc == 0) {
	rc = JS_Cmd_NewImaEntry(&command,
				"imaentry",
				machineName,
				nonceString,
				imaEntryString);
    }
    /* place the event log in a file if it is not already there */
    if (rc == 0) {
	rc = retrieveTPMLog(imaInputFilename);
    }
    /* open the IMA event log file */
    FILE *inFile = NULL;
    if (rc == 0) {
	inFile = fopen(imaInputFilename,"rb");	/* closed @2 */
	if (inFile == NULL) {
	    printf("ERROR: sendImaMeasurements: Unable to open event log file '%s'\n",
		   imaInputFilename);
	    rc = 1;
	}
    }
    /* skip over entries that have already been sent.  If end of file is reached, then either:

       the measurement log has been tampered, with entries deleted
       the server has a problem, asking for measurements that don't exist
    */
    ImaEvent 	imaEvent;
    int 	event;
    int 	endOfFile = FALSE;
    if (vverbose) printf("sendImaMeasurements: skipping to event %u\n", imaEntry);
    for (event = 0 ; (rc == 0) && (event < imaEntry) && !endOfFile ; event++) {
	if (rc == 0) {
	    IMA_Event_Init(&imaEvent);
	    rc = IMA_Event_ReadFile(&imaEvent,	/* freed by caller */
				    &endOfFile,
				    inFile,
				    TRUE);		/* little endian */
	    IMA_Event_Free(&imaEvent);
	}
	/* the measurements to be skipped had better still be there */
	if (rc == 0) {
	    if (endOfFile) {
		if (vverbose) printf("sendImaMeasurements: end of file skiping entry %u\n", event);
		rc = 1;
	    }
	}	
    }
    /* if not end of file, have more measurements to send */
    /* add number of first ima entry */
    if ((rc == 0) && !endOfFile) {
	rc = JS_Cmd_AddImaEntry(command,
				imaEntryString);
	
    }
    /* read and send the rest of the events, until end of file */
    for ( ; (rc == 0) && !endOfFile; event++) {
	if (rc == 0) {
	    if (vverbose) printf("sendImaMeasurements: reading event %u\n", event);
	    IMA_Event_Init(&imaEvent);
	    rc = IMA_Event_ReadFile(&imaEvent,	/* freed by caller */
				    &endOfFile,
				    inFile,
				    TRUE);		/* little endian */
	}
	if ((rc == 0) && !endOfFile) {
	    if (vverbose) IMA_Event_Trace(&imaEvent, TRUE);
	}
	if ((rc == 0) && !endOfFile) {
	    /* serialize and add this IMA event to the json command */
	    if (vverbose) printf("sendImaMeasurements: add entry %u\n", event);
	    rc = JS_Cmd_AddImaEvent(command,
				    &imaEvent,				     
				    event);
	}
	IMA_Event_Free(&imaEvent);
    }
    uint32_t cmdLength;
    uint8_t *cmdBuffer = NULL;
    uint32_t rspLength;
    uint8_t *rspBuffer = NULL;
    if (rc == 0) {
	rc = JS_ObjectSerialize(&cmdLength,
				(char **)&cmdBuffer,	/* freed @1 */
				command);		/* @1 */
    }
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,	/* freed @2 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(imaEntryResponseJson,		/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: sendImaMeasurements: response", *imaEntryResponseJson);
    }
    if (rc == 0) {
	rc = JS_Rsp_Ima(*imaEntryResponseJson);
    }
    if (inFile != NULL) {
	fclose(inFile);		/* @2 */
    }
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
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
    printf("[-bo biosentry only]\n");
    printf("[-io imaentry only]\n");
    printf("[-bq create bad quote]\n");
    printf("[-bt make random boot time (to defeat incremental event log)\n");
    printf("[-p pass count (default 1)]\n");
    printf("[-v verbose trace]\n");
    printf("[-vv very verbose trace]\n");
    printf("\n");
    exit(1);	
}

 
