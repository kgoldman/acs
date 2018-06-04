/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - 	Server Side SQL database     		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: serversql.h 1105 2017-12-06 22:27:11Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016.						*/
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

#ifndef SERVERSQL_H
#define SERVERSQL_H

#include <stdint.h>

#include <mysql/mysql.h>

#define QUERY_LENGTH_MAX 0x10000	/* FIXME */
#define TPM_SHA1_SIZE		20
#define TPM_NUM_PCR 		24
#define TPM_BIOS_PCR 		8
#define TPM_IMA_PCR 		10


uint32_t SQ_Connect(MYSQL **mysql);
uint32_t SQ_Query(MYSQL_RES **result,
		  MYSQL *mysql,
		  const char *query);
uint32_t SQ_FetchRow(MYSQL_ROW *row,
		     unsigned int rowOffset,
		     MYSQL_RES *result);
void SQ_FreeResult(MYSQL_RES *result);
void SQ_Close(MYSQL *mysql);

uint32_t SQ_GetBootTime(const char **boottime,
			MYSQL_RES **machineCertResult,
			MYSQL *mysql,
			const char *machineName);
uint32_t SQ_GetMachineEntry(char **machineId, 		/* freed by caller */
			    const char **tpmvendor,
			    const char **challenge,
			    const char **attestpub,
			    const char **ekcertificatepem,
			    const char **ekcertificatetext,
			    const char **akcertificatepem,
			    const char **akcertificatetext,
			    const char **enrolled,
			    const char **boottime,
			    int *imaevents,
			    const char **imapcr,
			    MYSQL_RES **machineResult,	/* freed by caller */
			    MYSQL *mysql,
			    const char *hostname);
uint32_t SQ_RemoveMachineEntry(MYSQL *mysql,
			       const char *hostname);

uint32_t SQ_GetAttestLogEntry(char **attestLogId, 
			      const char **boottime,
			      const char **timestamp,
			      const char **pcrselect,
			      const char **nonce,
			      const char **quoteverified,
			      const char **logverified,
			      MYSQL_RES **attestLogResult,
			      MYSQL *mysql,
			      const char *hostname);
uint32_t SQ_GetImaLogEntry(char **imaLogId,
			   const char **boottime,
			   const char **timestamp,
			   const char **imapcr,
			   const char **entrynum,
			   const char **ima_entry,
			   const char **badevent,
			   const char **nosig,
			   const char **nokey,
			   const char **badsig,
			   MYSQL_RES **imaLogResult,
			   MYSQL *mysql,
			   const char *hostname);
uint32_t SQ_GetAttestLogPCRs(char **attestLogId, 
			     const char *pcrsSha1[],
			     const char *pcrsSha256[],
			     MYSQL_RES **attestLogResult,
			     MYSQL *mysql,
			     const char *hostname);
uint32_t SQ_GetPreviousPcrs(const char *previousPcrsSha1[],
			    const char *previousPcrsSha256[],
			    MYSQL_RES **attestLogResult,
			    MYSQL *mysql,
			    const char *hostname,
			    const char *boottime);
uint32_t SQ_GetFirstPcrs(const char *firstPcrsSha1String[],
			 const char *firstPcrsSha256String[],
			 MYSQL_RES **firstPcrsResult,
			 MYSQL *mysql,
			 const char *hostname);
#endif
