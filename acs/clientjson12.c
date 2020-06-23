/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client JSON Handler			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientjson12.c 1607 2020-04-28 21:35:05Z kgoldman $		*/
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

#include <unistd.h>

#include <json/json.h>

#include "commonutils.h"
#include "commonjson.h"
#include "clientjson.h"
#include "clientjson12.h"
#include "eventlib.h"

extern int verbose;
extern int vverbose;

/* JS_Cmd_NewQuote12() begins a client command packet to send a quote packet

   "command":"quote12",
   "hostname":"name",
   "pcrdata":"value",
   "versioninfo":"value",
   "signature":"value",

   where name is the host name.
*/

uint32_t JS_Cmd_NewQuote12(json_object **command,	/* freed by caller */
			   const char *hostname,
			   const char *pcrDataString,
			   const char *versionInfoString,
			   const char *signatureString)
{
    int rc = 0;
    
    if (rc == 0) {
	rc = JS_ObjectNew(command);		/* freed @1 */
    }
    if (rc == 0) {
	/* command is quote*/
	json_object_object_add(*command, "command", json_object_new_string("quote12"));
	/* add client machine name */
	JS_Cmd_AddHostname(*command, hostname);
	/* add pcrdata, versioninfo, and signature */
	json_object_object_add(*command,
			       "pcrdata", json_object_new_string(pcrDataString));
	json_object_object_add(*command,
			       "versioninfo", json_object_new_string(versionInfoString));
	json_object_object_add(*command,
			       "signature", json_object_new_string(signatureString));
    }
    return rc;
}

/* JS_Cmd_AddEvent12() adds a BIOS event to the command json.

   The event is a TCG_PCR_EVENT2 structure.
   'lineNum' is the event number, a line (row) in the event log.

   "eventn":"hexascii event",

*/

uint32_t JS_Cmd_AddEvent12(json_object *command,
			   unsigned int lineNum,
			   TCG_PCR_EVENT *event)
{
    uint32_t rc = 0;
    char *eventString = NULL;
    char jsonKey[5+8+1];

    if (rc == 0) {
	rc = Structure_Print(&eventString,	/* freed @1 */
			     event,
			     (MarshalFunction_t)TSS_EVENT_Line_Marshal);
    }
    if (rc == 0) {
	sprintf(jsonKey, "event%u", lineNum);
	json_object_object_add(command, jsonKey, json_object_new_string(eventString));
    }
    free(eventString);	/* @1 */
    return rc;
}

