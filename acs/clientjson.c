/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client JSON Handler			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientjson.c 1183 2018-04-27 16:58:25Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2018					*/
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

#include <unistd.h>

#include <json/json.h>

#include "commonutils.h"
#include "commonjson.h"
#include "clientjson.h"

extern int verbose;
extern int vverbose;

/* JS_Cmd_Nonce() constructs a complete client command packet to get a nonce

   "command":"nonce",
   "hostname":"name",
   "userid":"user"

   where name is the host name and user is the user login name.
*/

uint32_t JS_Cmd_Nonce(uint32_t *length,
		      char **buffer,			/* freed by caller */
		      const char *commandString,	/* TPM 1.2 or 2.0 */
		      const char *machineName)
{
    int rc = 0;
    json_object *command = NULL;
    
    if (rc == 0) {
	rc = JS_ObjectNew(&command);		/* freed @1 */
    }
    if (rc == 0) {
	/* command is nonce */
	json_object_object_add(command, "command",
			       json_object_new_string(commandString));
	/* add client machine name */
	JS_Cmd_AddHostname(command, machineName);
	/* add user name */
	char *userid = getlogin();
	if (userid == NULL) {
	    userid = "unknown";
	}
	json_object_object_add(command, "userid", json_object_new_string(userid));
    }
    if (rc == 0) {
	rc = JS_ObjectSerialize(length,
				buffer,		/* freed by caller */
				command);	/* @1 */
    }
    return rc;
}

/* JS_Rsp_Nonce() handles the response to the nonce command of the form 

   "response":"nonce",
   "nonce":"0ac6c9ac76c9856cbe87c32324006786ac45b422d92930e6eb6c65533e203ca3",
   "pcrselect":"00000002000b03ff0000000403000400"

   It returns the nonce and pcr select values.
*/

uint32_t JS_Rsp_Nonce(const char **nonceString,
		      const char **pcrSelectString,
		      json_object *responseObj)
{
    int rc = 0;
    const char *responseString = NULL;

    if (rc == 0) {
	rc = JS_ObjectGetString(&responseString, "response", responseObj);
    }
    if (rc == 0) {
	if (strcmp(responseString, "nonce") != 0) {
	    printf("ERROR: JS_Rsp_Nonce: response %s is not nonce\n", responseString);
	    rc = 1;
	}
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(nonceString, "nonce", responseObj);
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(pcrSelectString, "pcrselect", responseObj);
    }
    return rc;
}

#ifdef TPM_TPM20

/* JS_Cmd_Quote() constructs a complete command client packet send a quote

   "command":"quote",
   "hostname":"name",
   "boottime":"2016-03-21 09:08:25"
   "pcrnsha1":"value",
   "pcrnsha256":"value",
   "quoted":"value",
   "signature":"value",

   where name is the host name.
*/

uint32_t JS_Cmd_Quote(uint32_t *length,
		      char **buffer,		/* freed by caller */
		      const char *hostname,
		      const char *boottime,
		      char pcrsha1[][(SHA1_DIGEST_SIZE * 2) + 1],
		      char pcrsha256[][(SHA256_DIGEST_SIZE * 2) + 1],
		      const char *quoted,
		      const char *signature)
{
    int rc = 0;
    int i;
    json_object *command = NULL;
    
    if (rc == 0) {
	rc = JS_ObjectNew(&command);		/* freed @1 */
    }
    if (rc == 0) {
	/* command is quote*/
	json_object_object_add(command, "command", json_object_new_string("quote"));
	/* add client machine name */
	JS_Cmd_AddHostname(command, hostname);
	/* add client boot time */
	json_object_object_add(command, "boottime", json_object_new_string(boottime));
	/* add pcrs */
	char objName[12];
	for (i = 0 ; i < 24 ; i++) {
	    sprintf(objName, "pcr%usha1", i);
	    json_object_object_add(command, objName, json_object_new_string(pcrsha1[i]));
	}
	for (i = 0 ; i < 24 ; i++) {
	    sprintf(objName, "pcr%usha256", i);
	    json_object_object_add(command, objName, json_object_new_string(pcrsha256[i]));
	}
	/* add quoted and signature */
	json_object_object_add(command, "quoted", json_object_new_string(quoted));
	json_object_object_add(command, "signature", json_object_new_string(signature));
    }
    if (rc == 0) {
	rc = JS_ObjectSerialize(length,
				buffer,		/* freed by caller */
				command);	/* @1 */
    }
    return rc;
}

#endif

/* JS_Rsp_Quote() handles the response to the quote command of the form 

   "response":"quote",

   It just checks that the response is quote.
*/

uint32_t JS_Rsp_Quote(json_object *responseObj)
{
    int rc = 0;
    const char *responseString = NULL;

    if (rc == 0) {
	rc = JS_ObjectGetString(&responseString, "response", responseObj);
    }
    if (rc == 0) {
	if (strcmp(responseString, "quote") != 0) {
	    printf("ERROR: JS_Rsp_Nonce: response %s is not quote\n", responseString);
	    rc = 1;
	}
    }
    return rc;
}

/* JS_Rsp_Bios() handles the response to the biosentry command of the form 

   "response":"biosentry"
   "imaentry":"0"
   
   It returns the imaentry.
*/

uint32_t JS_Rsp_Bios(const char **imaentryString,
		     json_object *responseObj)
{
    int rc = 0;
    const char *responseString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&responseString, "response", responseObj);
    }
    if (rc == 0) {
	if (strcmp(responseString, "biosentry") != 0) {
	    printf("ERROR: JS_Rsp_Bios: response %s is not biosentry\n", responseString);
	    rc = 1;
	}
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(imaentryString, "imaentry", responseObj);
    }
    return rc;
}

/* JS_Rsp_Ima() handles the response to the imaentry command of the form 

   "response":"imaentry"
   
*/

uint32_t JS_Rsp_Ima(json_object *responseObj)
{
    int rc = 0;
    const char *responseString = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&responseString, "response", responseObj);
    }
    if (rc == 0) {
	if (strcmp(responseString, "imaentry") != 0) {
	    printf("ERROR: JS_Rsp_Ima: response %s is not imaentry\n", responseString);
	    rc = 1;
	}
    }
    return rc;
}

#ifdef TPM_TPM20

/* JS_Cmd_AddEvent() adds a BIOS event to the command json.

   The event is a TCG_PCR_EVENT2 structure.
   'lineNum' is the event number, a line (row) in the event log.

   "eventn":"hexascii event",

*/

uint32_t JS_Cmd_AddEvent(json_object *command,
			 unsigned int lineNum,
			 TCG_PCR_EVENT2 *event2)
{
    uint32_t rc = 0;
    char *eventString = NULL;
    char jsonKey[5+8+1];

    if (rc == 0) {
	rc = Structure_Print(&eventString,	/* freed @1 */
			     event2,
			     (MarshalFunction_t)TSS_EVENT2_Line_Marshal);
    }
    if (rc == 0) {
	sprintf(jsonKey, "event%u", lineNum);
	json_object_object_add(command, jsonKey, json_object_new_string(eventString));
    }
    free(eventString);	/* @1 */
    return rc;
}

#endif

/* JS_Cmd_AddImaEvent() adds an IMA event to the command json.

   The event is an ImaEvent structure.
   'lineNum' is the event number, a line (row) in the event log.

   "eventn":"hexascii event",

*/

#ifndef TPM_ACS_NOIMA

uint32_t JS_Cmd_AddImaEvent(json_object *command,
			    ImaEvent 	*imaEvent,
			    unsigned int lineNum)
{
    uint32_t rc = 0;
    uint16_t written = 0;
    uint8_t *eventBin = NULL;
    char *eventString = NULL;
    char jsonKey[5+8+1];	/* FIXME */

    /* marshal the ImaEvent structure to binary */
    if (rc == 0) {
	rc = TSS_Structure_Marshal(&eventBin,		/* freed @1 */
				   &written,
				   imaEvent,
				   (MarshalFunction_t)IMA_Event_Marshal);
    }
    /* allocate for the ImaEvent string */ 
    if (rc == 0) {
	eventString = malloc((written * 2) + 1);	/* freed @2 */
	if (eventString == NULL) {
	    printf("ERROR: JS_Cmd_AddImaEvent: allocating %u bytes\n", (written * 2) + 1);
	    rc = 1;
	}
    }
    /* convert binary to hexascii for json */
    if (rc == 0) {
	Array_Print(eventString, NULL, FALSE, eventBin, written);
    }
    if (rc == 0) {
	sprintf(jsonKey, "event%u", lineNum);
	json_object_object_add(command, jsonKey, json_object_new_string(eventString));
    }
    free(eventBin);	/* @1 */
    free(eventString);	/* @2 */
    return rc;
}

/* JS_Cmd_AddImaEntry() adds a json item:  imaentry:imaEntryString

   where imaEntryString is an integer reflecting the first ima entry to be sent.
*/

uint32_t JS_Cmd_AddImaEntry(json_object *command,
			    const char *imaEntryString)
{
    int rc = 0;
    json_object_object_add(command, "imaentry", json_object_new_string(imaEntryString));
    return rc;
}

#endif

/* JS_Cmd_NewBiosEntry() begins a client command packet to send BIOS entries

   "command":"biosentry",
   "hostname":"name",
   "nonce":"1298d83cdd8c50adb58648d051b1a596b66698758b8d0605013329d0b45ded0c",

*/

uint32_t JS_Cmd_NewBiosEntry(json_object **command,	/* freed by caller */
			     const char *commandString,	/* TPM 1.2 or 2.0 */
			     const char *hostname,
			     const char *nonce)
{
    int rc = 0;
    
    if (rc == 0) {
	rc = JS_ObjectNew(command);		/* freed by caller */
    }
    if (rc == 0) {
	/* command is biosentry */
	json_object_object_add(*command, "command", json_object_new_string(commandString));
	/* add client machine name */
	JS_Cmd_AddHostname(*command, hostname);
	/* add nonce */
	json_object_object_add(*command, "nonce", json_object_new_string(nonce));
    }
    return rc;
}

/* JS_Cmd_NewImaEntry() begins a client command packet to send BIOS entries

   "command":"imaentry",
   "hostname":"name",
   "imaentry":"0"

*/

uint32_t JS_Cmd_NewImaEntry(json_object **command,	/* freed by caller */
			    const char *commandString,	/* TPM 1.2 or 2.0 */
			    const char *hostname,
			    const char *nonceString,
			    const char *imaEntryString)
{
    int rc = 0;
    
    if (rc == 0) {
	rc = JS_ObjectNew(command);		/* freed by caller */
    }
    if (rc == 0) {
	/* command is biosentry */
	json_object_object_add(*command, "command", json_object_new_string(commandString));
	/* add client machine name */
	JS_Cmd_AddHostname(*command, hostname);
	/* add nonce */
	json_object_object_add(*command, "nonce", json_object_new_string(nonceString));
	/* add IMA entry number */
	json_object_object_add(*command, "imaentry", json_object_new_string(imaEntryString));
    }
    return rc;
}

/* JS_Cmd_AddHostname() adds a json item

   hostname:name

   If machineName is NULL, use the client host name.  If not NULL, use machineName.
*/

void JS_Cmd_AddHostname(json_object *command, const char *machineName)
{
    /* add client machine name */
    char hostname[HOST_NAME_MAX +1];
    hostname[HOST_NAME_MAX] = '\0';
    if (machineName == NULL) {
	gethostname(hostname, HOST_NAME_MAX);
    }
    else {
	strncpy(hostname, machineName, HOST_NAME_MAX);
    }
    hostname[HOST_NAME_MAX] = '\0';
    /* POSIX.1 says that if truncation occurs, then it is unspecified whether the returned buffer
       includes a terminating null byte. */
    json_object_object_add(command, "hostname", json_object_new_string(hostname));
    return;
}

/* JS_Cmd_EnrollRequest() constructs a complete client command packet enrollment request

   {
   "command":"enrollrequest",
   "hostname":"name",
   "tpmvendor":vendor",
   "ekcert":"hexascii",
   "akpub":"hexascii"
   }

   where

   ekcert is the TPM EK certificate
   akpub is a marahalled TPMT_PUBLIC

*/

uint32_t JS_Cmd_EnrollRequest(uint32_t *length,
			      char **buffer,			/* freed by caller */
			      const char *commandString,	/* TPM 1.2 or 2.0 */
			      const char *tpmVendor,
			      const char *ekCertificateString,
			      const char *attestPubString,
    			      const char *machineName)
{
    int rc = 0;
    json_object *command = NULL;
    
    if (rc == 0) {
	rc = JS_ObjectNew(&command);		/* freed @1 */
    }
    if (rc == 0) {
	/* command is nonce */
	json_object_object_add(command, "command", json_object_new_string(commandString));
	/* add client machine name */
	JS_Cmd_AddHostname(command, machineName);
	json_object_object_add(command, "tpmvendor", json_object_new_string(tpmVendor));
	json_object_object_add(command, "ekcert", json_object_new_string(ekCertificateString));
	json_object_object_add(command, "akpub", json_object_new_string(attestPubString));
    }
    if (rc == 0) {
	rc = JS_ObjectSerialize(length,
				buffer,		/* freed by caller */
				command);	/* @1 */
    }
    return rc;
}

/* JS_Cmd_EnrollCert() constructs a complete client command packet enrollment attestation key
   certificate request.  The certificate is the decrypted (recovered) attestation key certificate.

   {
   "command":"enrollcert",
   "hostname":"name",
   "challenge":"hexascii",
   }

   where akcert is the DER format attesation key certificate

*/

uint32_t JS_Cmd_EnrollCert(uint32_t *length,
			   char **buffer,		/* freed by caller */
			   const char *challengeString,
			   const char *machineName)
{
    int rc = 0;
    json_object *command = NULL;
    
    if (rc == 0) {
	rc = JS_ObjectNew(&command);		/* freed @1 */
    }
    if (rc == 0) {
	/* command is nonce */
	json_object_object_add(command, "command", json_object_new_string("enrollcert"));
	/* add client machine name */
	JS_Cmd_AddHostname(command, machineName);
	json_object_object_add(command, "challenge", json_object_new_string(challengeString));
    }
    if (rc == 0) {
	rc = JS_ObjectSerialize(length,
				buffer,		/* freed by caller */
				command);	/* @1 */
    }
    return rc;
}


/* JS_ObjectUnmarshal() parses a string to a json object
   
   The object must be freed (json_object_put) by the caller.
*/

uint32_t JS_ObjectUnmarshal(json_object **object,		/* freed by caller */
			    const uint8_t *rspBuffer)
{
    int rc = 0;
    *object= json_tokener_parse((char *)rspBuffer);
    if (*object == NULL) {
	printf("ERROR: JS_ObjectUnmarshal: could not parse json string\n");
	rc = 1;
    }
    return rc;
}

/* JS_ObjectTrace() prints an optional message, and then the json object */

void JS_ObjectTrace(const char *message,
		    json_object *object)
{
    /* print optional message */
    if (message != NULL) {
	printf("%s\n", message);
    }
    const char *string = NULL;
    string = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PRETTY);
    if (string == NULL) {
	printf("ERROR: JS_ObjectTrace: converting json object to string\n");
    }
    else {
	printf("%s\n", string);
    }
    return;
}


