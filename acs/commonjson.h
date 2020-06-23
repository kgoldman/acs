/********************************************************************************/
/*										*/
/*	TPM 2.0 Attestation - Common Client and Server JSON functions		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commonjson.h 1607 2020-04-28 21:35:05Z kgoldman $		*/
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

#ifndef COMMONJSON_H
#define COMMONJSON_H

#include <json/json.h>

#define ACS_JSON_COMMAND_MAX 		32	/* command and response */
#define ACS_JSON_BOOL_MAX		4
#define ACS_JSON_CREDENTIALBLOB_MAX	512
#define ACS_JSON_SECRET_MAX		1024
#define ACS_JSON_PEMCERT_MAX		4096
#define ACS_JSON_HASH_MAX		128
#define ACS_JSON_PCRSELECT_MAX		128
#define ACS_JSON_HOSTNAME_MAX		128
#define ACS_JSON_USERID_MAX		32
#define ACS_JSON_TIME_MAX		64
#define ACS_JSON_TPM_MAX		32
#define ACS_JSON_PUB_MAX		2048
#define ACS_JSON_QUOTED_MAX		1024
#define ACS_JSON_SIGNATURE_MAX		1024
#define ACS_JSON_EVENTNUM_MAX		16
#define ACS_JSON_PCRDATA_MAX		64
#define ACS_JSON_VERSIONINFO_MAX	48
#define ACS_JSON_EVENT_MAX		0x100000	/* 1 Mbytes for firmware */

/* this is related to QUERY_LENGTH_MAX */
#define ACS_JSON_EVENT_DBMAX		0x4000		/* 16 kbytes into DB */

uint32_t JS_ObjectNew(json_object **object);
uint32_t JS_ObjectNewArray(json_object **object);
void     JS_ObjectFree(json_object *object);
uint32_t JS_ObjectSerialize(uint32_t *length,
			    char **buffer,
			    json_object *object);
uint32_t JS_ObjectGetString(const char **string,
			    const char *key,
			    size_t maxLength,
			    json_object *object);
uint32_t JS_ObjectGetStringNull(const char **string,
				const char *key,
				size_t maxLength,
				json_object *object);
uint32_t JS_ObjectGetStringMalloc(char **stringMalloc,
				  const char *key,
				  size_t maxLength,
				  json_object *object);


#endif
