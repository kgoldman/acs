/********************************************************************************/
/*										*/
/*	TPM 2.0 Attestation - Common Client / Server Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commonutils.h 1167 2018-04-18 18:38:04Z kgoldman $		*/
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

#ifndef COMMONUTILS_H
#define COMMONUTILS_H

#include <stdio.h>
#include <stdint.h>

#define TPM_NUM_PCR 		24
#define TPM_SHA1_SIZE		20
#define TPM_SHA256_SIZE		32
#define ERR_STRUCTURE		1	/* FIXME need better error codes */

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

void Array_Print(char *string, const char *name, int newlines,
		 const unsigned char *data, unsigned int len);
uint32_t Array_PrintMalloc(char **string,
			   const uint8_t *data,
			   uint32_t len);
uint32_t Array_Scan(unsigned char **data,
		    size_t *len,
		    const char *string);

#include <tss2/tss.h>
#include <tss2/tssutils.h>

uint32_t Structure_Print(char 			**string,	/* freed by caller */
			void 			*structure,
			MarshalFunction_t 	marshalFunction);
uint32_t Structure_Scan(void 			*structure,
			UnmarshalFunction_t 	unmarshalFunction,
			const char 		*string);

uint32_t makeAkFilenames(char 		*akpubFullName,
			 char 		*akprivFullName,
			 size_t 	akFullNameSize,
			 const char 	*akpubFilename,			 
			 const char 	*akprivFilename,
			 const char 	*machineName);
#endif
