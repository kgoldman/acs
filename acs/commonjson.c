/********************************************************************************/
/*										*/
/*	TPM 2.0 Attestation - Common Client and Server JSON functions		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commonjson.c 1607 2020-04-28 21:35:05Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2020.					*/
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
#include <string.h>

#include "commonerror.h"
#include "commonutils.h"

#include "commonjson.h"

extern int verbose;
extern int vverbose;

/* JS_ObjectNew() allocates a new json object.  It checks for failures.
 */

uint32_t JS_ObjectNew(json_object **object)
{
    int rc = 0;
   
    *object = json_object_new_object();
    if (*object == NULL) {
	rc = ASE_OUT_OF_MEMORY;
    }
    return rc;
}

uint32_t JS_ObjectNewArray(json_object **object)
{
    int rc = 0;
   
    *object = json_object_new_array();
    if (*object == NULL) {
	rc = 1;
    }
    return rc;
}

/* JS_ObjectFree() frees the json object.
 */

void JS_ObjectFree(json_object *object)
{
    if (object != NULL) {
	json_object_put(object);
    }
    return;
}

/* JS_Serialize() mallocs a buffer and copies the serialized json object into the buffer.

   It then frees the json object
*/

uint32_t JS_ObjectSerialize(uint32_t *length,
			    char **buffer,		/* freed by caller */
			    json_object *object)	/* freed here */
{
    int rc = 0;
    const char *p = NULL;

    if (rc == 0) {
	p = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PRETTY);
	if (p == NULL) {
	    printf("ERROR: JS_ObjectSerialize: converting json object to string\n");
	    rc = ASE_JSON_SERIALIZE;
	}
    }
    if (rc == 0) {
	if (verbose) printf("INFO: JS_ObjectSerialize:\n%s\n", p);
	*length = strlen(p)+1;
	*buffer = malloc(*length);
	if (*buffer == NULL) {
	    printf("ERROR: JS_ObjectSerialize: mallocing %u\n", *length);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	strcpy(*buffer, p);
    }
    json_object_put(object);	/* freed here */
    return rc;
}

/* JS_ObjectGetString() returns the value string corresponding to the key string in the json
   object.

   If the length of the key is greater than maxLength, then return ACE_PACKET_LENGTH
*/

uint32_t JS_ObjectGetString(const char **string,
			    const char *key,
			    size_t maxLength,
			    json_object *object)
{
    uint32_t rc = 0;
    json_bool brc;
    json_object *valueJson = NULL;

    if (rc == 0) {
	brc = json_object_object_get_ex(object, key, &valueJson);
	if (brc == FALSE) {
	    printf("ERROR: JS_ObjectGetString: getting key: %s\n", key);
	    rc = ACE_JSON_KEY;
	}
    }
    if (rc == 0) {
	*string = json_object_get_string(valueJson);
	if (vverbose) printf("JS_ObjectGetString: key: %s string: %s\n",
			     key, *string);
    }
    if (rc == 0) {
	size_t length = strlen(*string);
	if (length > maxLength) {
	    printf("ERROR: JS_ObjectGetString: key %s, length %lu > max %lu, \n",
		   key, (unsigned long)length, (unsigned long)maxLength);
	    rc = ACE_PACKET_LENGTH;
	}
    }
    return rc;
}

/* JS_ObjectGetStringNull() returns the value string corresponding to the key string in the json
   object.

   If the key is missing, returns *string = NULL
   If the length of the key is greater than maxLength, then return ACE_PACKET_LENGTH
*/

uint32_t JS_ObjectGetStringNull(const char **string,
				const char *key,
				size_t maxLength,
				json_object *object)
{
    uint32_t rc = 0;
    json_bool brc;
    json_object *valueJson = NULL;

    if (rc == 0) {
	brc = json_object_object_get_ex(object, key, &valueJson);
	if (brc == FALSE) {
	    *string = NULL;
	}
    }
    if ((rc == 0) && brc) {
	*string = json_object_get_string(valueJson);
	if (vverbose) printf("JS_ObjectGetStringNull: key: %s string: %s\n",
			     key, *string);
    }
    if ((rc == 0) && brc) {
	size_t length = strlen(*string);
	if (length > maxLength) {
	    printf("ERROR: JS_ObjectGetStringNull: key %s, length %lu > max %lu, \n",
		   key, (unsigned long)length, (unsigned long)maxLength);
	    rc = ACE_PACKET_LENGTH;
	}
    }
    return rc;
}

/* JS_ObjectGetStringMalloc() is similar to JS_ObjectGetString() but returns a
   malloced string rather than a const.  The intended use is a large string that
   must be truncated before storing in the database.
*/
			    
uint32_t JS_ObjectGetStringMalloc(char **stringMalloc,	/* freed by caller */
				  const char *key,
				  size_t maxLength,
				  json_object *object)
{
    int 	rc = 0;
    const char 	*string;
    size_t	stringLength;
    
    if (rc == 0) {
	rc = JS_ObjectGetString(&string, key, maxLength, object);
    }
    if (rc == 0) {
	stringLength = strlen(string);
	*stringMalloc = malloc(stringLength+1);		/* +1 for the nul terminator */
	if (*stringMalloc == NULL) {
	    printf("ERROR: JS_ObjectGetStringMalloc: could not malloc %lu bytes, key %s\n",
		   (unsigned long)stringLength, key);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	strcpy(*stringMalloc, string);
    }
    return rc;
}
