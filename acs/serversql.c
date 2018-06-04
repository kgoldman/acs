/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - 	Server Side SQL database     		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: serversql.c 1171 2018-04-19 18:22:21Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2018.					*/
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mysql/mysql.h>

#include "commonerror.h"

#include "serversql.h"

extern int verbose;
extern int vverbose;

/* SQ_Connect() connects to the local ACS database, currently hard coded to tpm2.

   On success, returns the MYSQL object.
 */

uint32_t SQ_Connect(MYSQL **mysql)	/* close by caller, see SQ_Close() */
{
    uint32_t  	rc = 0;
    MYSQL *mysqlconnection = NULL;

    if (rc == 0) {
	*mysql = mysql_init(NULL);
	const char *sqlHost = getenv("ACS_SQL_HOST");		/* DB host */
	const char *sqlUserID = getenv("ACS_SQL_USERID"); 	/* user */
	const char *sqlPassword = getenv("ACS_SQL_PASSWORD"); 	/* passwd */
	const char *sqlDatabase = getenv("ACS_SQL_DATABASE");
	if (sqlDatabase == NULL) {
	    sqlDatabase = "tpm2";
	}
	const char *sqlPort = getenv("ACS_SQL_PORT");
	unsigned int port = 0;
	if (sqlPort != NULL) {
	    sscanf(sqlPort, "%u", &port);
	}
	if (vverbose) printf("SQ_Connect: host %s port %u userid %s password %s database %s\n",
			     sqlHost, port, sqlUserID, sqlPassword, sqlDatabase);
	mysqlconnection = mysql_real_connect(*mysql,
					     sqlHost,		/* host, NULL is localhost */
					     sqlUserID, 	/* user, NULL is current user */
					     sqlPassword, 	/* passwd, NULL is empty */
					     sqlDatabase,	/* database, default tpm2 */
					     port, 		/* port, default 0 */
					     NULL, 		/* unix_socket */
					     0); 		/* clientflag */
	if (mysqlconnection == NULL) {
	    printf("ERROR: SQ_Connect: mysql_real_connect failed\n");
	    mysql_error(*mysql);
	    return ASE_SQL_CONNECT;
	}
    }    
    return rc;
}

/* SQ_Query() runs 'query' against the DB mysql.

   If result is not NULL (select statement), stores the result of the query.  Use SQ_FetchRow() to
   get a result row.

   Otherwise (insert, update), there is no result.
*/

uint32_t SQ_Query(MYSQL_RES **result,	/* freed by caller, see SQ_FreeResult() */
		  MYSQL *mysql,
		  const char *query)
{
    uint32_t  	rc = 0;
    int		irc = 0;

    if (rc == 0) {
	if (vverbose) printf("SQ_Query: sql statement:\n%s\n", query);
	irc = mysql_query(mysql, query);
	if (irc != 0) {
	    printf("ERROR: SQ_Query: mysql_query failed\n");
	    mysql_error(mysql);
	    rc = ASE_SQL_QUERY;
	}
    }
    if (rc == 0) {
	if (result != NULL) {
	    *result = mysql_store_result(mysql);
	    if (*result == NULL) {
		printf("ERROR: SQ_Query: mysql_store_result failed\n");
		mysql_error(mysql);
		rc = ASE_SQL_QUERY;
	    }
	}
    }
    return rc;
}

/* SQ_FetchRow() returns a selected row.

   If rowOffset is 0, the last row is returned.  If rowOffset is non-zero, a previous row is
   returned.

   This function does not currently distinguish zero rows, or an offset greater than the number of
   rows from other errors.

*/

uint32_t SQ_FetchRow(MYSQL_ROW *row,		/* does not require a free */
		     unsigned int rowOffset,
		     MYSQL_RES *result)
{
    uint32_t  	rc = 0;

    my_ulonglong numRows;

    if (rc == 0) {
	/* how many rows were returned */
	numRows = mysql_num_rows(result);
	if (vverbose) printf("Number of rows %lu\n", (unsigned long)numRows);
	if (numRows == 0) {
	    printf("ERROR: SQ_FetchRow: returned no rows\n");
	    rc = ASE_SQL_QUERY;
	}
	else if (numRows <= rowOffset) {	/* = because rows are zero based */
	    printf("ERROR: SQ_FetchRow: returned %lu rows, offset is %u\n",
		   (unsigned long)numRows, rowOffset);
	    rc = ASE_SQL_QUERY;
	}
    }
    /* return the last row */
    if (rc == 0) {
	mysql_data_seek(result, numRows-1-rowOffset);
	*row = mysql_fetch_row(result);
    }
    return rc;
}

/* SQ_FreeResult() frees the result of the mysql query.

   If result is NULL, this is a noop.
*/

void SQ_FreeResult(MYSQL_RES *result)
{
    if (result != NULL) {
	mysql_free_result(result);
    }
    return;
}

/* SQ_Close() closes the mysql connection.

   If mysql is NULL, this is a noop.
*/

void SQ_Close(MYSQL *mysql)
{
    if (mysql != NULL) {
	mysql_close(mysql);
    }
    return;
}

/* SQ_GetMachineEntry() gets active machine entry for the hostname.

   Columns that have a non-NULL input parameter are returned.
*/

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
			    const char *hostname)
{
    uint32_t	rc = 0;
    char query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	sprintf(query,
		"select id, tpmvendor, challenge, attestpub, "
		"ekcertificatepem, ekcertificatetext, "
		"akcertificatepem, akcertificatetext, "
		"enrolled, boottime, imaevents, imapcr "
		"from machines where hostname = '%s'",
		hostname);
	rc = SQ_Query(machineResult,	/* freed by caller */
		      mysql, query);
    }
    MYSQL_ROW machineRow = NULL; 
    if (rc == 0) {
	rc = SQ_FetchRow(&machineRow,
			 0,			/* get last row, should be just one */
			 *machineResult);
    }
    if (rc == 0) {
	if (machineId != NULL) {
	    if (vverbose) printf("SQ_GetMachineEntry: machineId %s\n", machineRow[0]);
	    if (machineRow[0] != NULL) {
		*machineId = malloc(strlen(machineRow[0]) +1);	/* freed by caller */
		if (*machineId == NULL) {
		    ; /* FIXME this should never fail because the Id is small.  Better to convert to
			 int and use that */
		}
		else {
		    strcpy(*machineId, machineRow[0]);
		}
	    }
	    else {
		*machineId = NULL;
	    }
	}
	if (tpmvendor != NULL) {
	    *tpmvendor = machineRow[1];
	    if (vverbose) printf("SQ_GetMachineEntry: tpmvendor %s\n",
				 *tpmvendor);
	}
	if (challenge != NULL) {
	    *challenge = machineRow[2];
	    if (vverbose) printf("SQ_GetMachineEntry: challenge %s\n",
				 *challenge);
	}
	if (attestpub != NULL) {
	    *attestpub = machineRow[3];
	    if (vverbose) printf("SQ_GetMachineEntry: attestpub %s\n",
				 *attestpub);
	}
	if (ekcertificatepem != NULL) {
	    *ekcertificatepem = machineRow[4];
#if 0
	    if (vverbose) printf("SQ_GetMachineEntry: ekcertificatepem %s\n",
				 *ekcertificatepem);
#endif
	}
	if (ekcertificatetext != NULL) {
	    *ekcertificatetext = machineRow[5];
#if 0
	    if (vverbose) printf("SQ_GetMachineEntry: ekcertificatetext %s\n",
				 *ekcertificatetext);
#endif
	}
	if (akcertificatepem != NULL) {
	    *akcertificatepem = machineRow[6];
#if 0
	    if (vverbose) printf("SQ_GetMachineEntry: akcertificatepem %s\n",
				 *akcertificatepem);
#endif
	}
	if (akcertificatetext != NULL) {
	    *akcertificatetext = machineRow[7];
#if 0
	    if (vverbose) printf("SQ_GetMachineEntry: akcertificatetext %s\n",
				 *akcertificatetext);
#endif
	}
	if (enrolled != NULL) {
	    *enrolled = machineRow[8];
	    if (vverbose) printf("SQ_GetMachineEntry: enrolled %s\n",
				 *enrolled);
	}
	if (boottime != NULL) {
	    *boottime = machineRow[9];
	    if (vverbose) printf("SQ_GetMachineEntry: boottime %s\n",
				 *boottime);
	}
	if (imaevents != NULL) {
	    if (machineRow[10] != NULL) {
		*imaevents = atoi(machineRow[10]);
	    }
	    else {
		*imaevents = 0;
	    }
	    if (vverbose) printf("SQ_GetMachineEntry: imaevents %u\n",
				 *imaevents);
	}
	if (imapcr != NULL) {
	    *imapcr = machineRow[11];
	    if (vverbose) printf("SQ_GetMachineEntry: imapcr %s\n",
				 *imapcr);
	}
     }
    return rc;
}

/* SQ_GetAttestLogEntry() gets the most recent attestlog entry for the hostname.

   Columns that have a non-NULL input parameter are returned.

   Since attestLogId is required for subsequent DB calls, it must persist.  Therefore, a malloced
   copy is returned.  It must be freed by the caller.

   The other entries (so far) need not persist.
*/

uint32_t SQ_GetAttestLogEntry(char **attestLogId, 		/* freed by caller */
			      const char **boottime,
			      const char **timestamp,
			      const char **nonce,
			      const char **pcrselect,
			      const char **quoteverified,
			      const char **logverified,
			      MYSQL_RES **attestLogResult,	/* freed by caller */
			      MYSQL *mysql,
			      const char *hostname)
{
    uint32_t	rc = 0;
    char query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	sprintf(query,
		"select id, boottime, timestamp, nonce, pcrselect, quoteverified, logverified "
		"from attestlog where hostname = '%s' order by id",
		hostname);
	rc = SQ_Query(attestLogResult,
		      mysql, query);
    }
    MYSQL_ROW attestLogRow = NULL; 
    if (rc == 0) {
	rc = SQ_FetchRow(&attestLogRow,
			 0,			/* get last row */
			 *attestLogResult);
    }
    /* the row evidently disappears at the next DB call, so save a copy for DB updates */ 
   if (rc == 0) {
	if (attestLogId != NULL) {
	    if (vverbose) printf("SQ_GetAttestLogEntry: attestLogId %s\n", attestLogRow[0]);
	    if (attestLogRow[0] != NULL) {
		*attestLogId = malloc(strlen(attestLogRow[0]) +1);	/* freed by caller */
		if (*attestLogId == NULL) {
		    ; /* FIXME this should never fail because the Id is small.  Better to convert to
			 int and use that */
		}
		else {
		    strcpy(*attestLogId, attestLogRow[0]);
		}
	    }
	    else {
		*attestLogId = NULL;
	    }
	}
	if (boottime != NULL) {
	    *boottime = attestLogRow[1];
	    if (vverbose) printf("SQ_GetAttestLogEntry: boottime %s\n", *boottime);
	}
	if (timestamp != NULL) {
	    *timestamp = attestLogRow[2];
	    if (vverbose) printf("SQ_GetAttestLogEntry: timestamp %s\n", *timestamp);
	}
	if (nonce != NULL) {
	    *nonce = attestLogRow[3];
	    if (vverbose) printf("SQ_GetAttestLogEntry: nonce %s\n", *nonce);
	}
	if (pcrselect != NULL) {
	    *pcrselect = attestLogRow[4];
	    if (vverbose) printf("SQ_GetAttestLogEntry: pcrselect %s\n", *pcrselect);
	}
	if (quoteverified != NULL) {
	    *quoteverified = attestLogRow[5];
	    if (vverbose) printf("SQ_GetAttestLogEntry: quoteverified %s\n", *quoteverified);
	}
	if (logverified != NULL) {
	    *logverified = attestLogRow[6];
	    if (vverbose) printf("SQ_GetAttestLogEntry: logverified %s\n", *logverified);
	}
    }
    return rc;
}

/* SQ_GetImaLogEntry() gets the most recent imalog entry for the hostname.

   Columns that have a non-NULL input parameter are returned.

   Since imaLogId is required for subsequent DB calls, it must persist.  Therefore, a malloced
   copy is returned.  It must be freed by the caller.

   The other entries (so far) need not persist.
*/

uint32_t SQ_GetImaLogEntry(char **imaLogId, 		/* freed by caller */
			   const char **boottime,
			   const char **timestamp,
			   const char **imapcr,
			   const char **entrynum,
			   const char **ima_entry,
			   const char **badevent,
			   const char **nosig,
			   const char **nokey,
			   const char **badsig,
			   MYSQL_RES **imaLogResult,	/* freed by caller */
			   MYSQL *mysql,
			   const char *hostname)
{
    uint32_t	rc = 0;
    char query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	sprintf(query,
		"select id, boottime, timestamp, imapcr, entrynum, "
		"ima_entry, badevent, nosig, nokey, badsig "
		"from imalog where hostname = '%s' order by id",
		hostname);
	rc = SQ_Query(imaLogResult,
		      mysql, query);
    }
    MYSQL_ROW imaLogRow = NULL; 
    if (rc == 0) {
	rc = SQ_FetchRow(&imaLogRow,
			 0,			/* get last row */
			 *imaLogResult);
    }
    /* the row evidently disappears at the next DB call, so save a copy for DB updates */ 
    if (rc == 0) {
	if (imaLogId != NULL) {
	    if (vverbose) printf("SQ_GetImaLogEntry: imaLogId %s\n", imaLogRow[0]);
	    if (imaLogRow[0] != NULL) {
		*imaLogId = malloc(strlen(imaLogRow[0]) +1);	/* freed by caller */
		if (*imaLogId == NULL) {
		    ; /* FIXME this should never fail because the Id is small.  Better to convert to
			 int and use that */
		}
		else {
		    strcpy(*imaLogId, imaLogRow[0]);
		}
	    }
	    else {
		*imaLogId = NULL;
	    }
	}
	if (boottime != NULL) {
	    *boottime = imaLogRow[1];
	    if (vverbose) printf("SQ_GetImaLogEntry: boottime %s\n", *boottime);
	}
	if (timestamp != NULL) {
	    *timestamp = imaLogRow[2];
	    if (vverbose) printf("SQ_GetImaLogEntry: timestamp %s\n", *timestamp);
	}
	if (imapcr != NULL) {
	    *imapcr = imaLogRow[3];
	    if (vverbose) printf("SQ_GetImaLogEntry: imapcr %s\n", *imapcr);
	}
	if (entrynum != NULL) {
	    *entrynum = imaLogRow[4];
	    if (vverbose) printf("SQ_GetImaLogEntry: entrynum %s\n", *entrynum);
	}
	if (ima_entry != NULL) {
	    *ima_entry = imaLogRow[5];
	    if (vverbose) printf("SQ_GetImaLogEntry: ima_entry %s\n", *ima_entry);
	}
	if (badevent != NULL) {
	    *badevent = imaLogRow[6];
	    if (vverbose) printf("SQ_GetImaLogEntry: badevent %s\n", *badevent);
	}
	if (nosig != NULL) {
	    *nosig = imaLogRow[7];
	    if (vverbose) printf("SQ_GetImaLogEntry:nosig %s\n", *nosig);
	}
	if (nokey != NULL) {
	    *nokey = imaLogRow[8];
	    if (vverbose) printf("SQ_GetImaLogEntry: nokey %s\n", *nokey);
	}
	if (badsig != NULL) {
	    *badsig = imaLogRow[9];
	    if (vverbose) printf("SQ_GetImaLogEntry: badsig %s\n", *badsig);
	}
    }
    return rc;
}

uint32_t SQ_RemoveMachineEntry(MYSQL *mysql,
			       const char *hostname)
{
    uint32_t	rc = 0;
    int		irc = 0;
    char 	query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	sprintf(query,
		"delete from machines where hostname = '%s'", hostname);
	if (vverbose) printf("SQ_RemoveMachineEntry: sql statement:\n%s\n", query);
	irc = mysql_query(mysql, query);
	if (irc != 0) {
	    printf("ERROR: SQ_Query: mysql_query failed\n");
	    mysql_error(mysql);
	    rc = ASE_SQL_QUERY;
	}
    }
    return rc;
}

/* SQ_GetAttestLogPCRs() gets the most recent attestlog entry for the hostname.

   Returns the PCRs
*/

uint32_t SQ_GetAttestLogPCRs(char **attestLogId, 		/* freed by caller */
			     const char *pcrsSha1[],
			     const char *pcrsSha256[],
			     MYSQL_RES **attestLogResult,	/* freed by caller */
			     MYSQL *mysql,
			     const char *hostname)
{
    uint32_t	rc = 0;
    char 	query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	sprintf(query,
		"select id, "
		"pcr00sha1, pcr01sha1, pcr02sha1, pcr03sha1, "
		"pcr04sha1, pcr05sha1, pcr06sha1, pcr07sha1, "
		"pcr08sha1, pcr09sha1, pcr10sha1, pcr11sha1, "
		"pcr12sha1, pcr13sha1, pcr14sha1, pcr15sha1, "
		"pcr16sha1, pcr17sha1, pcr18sha1, pcr19sha1, "
		"pcr20sha1, pcr21sha1, pcr22sha1, pcr23sha1, "
		"pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, "
		"pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256, "
		"pcr08sha256, pcr09sha256, pcr10sha256, pcr11sha256, "
		"pcr12sha256, pcr13sha256, pcr14sha256, pcr15sha256, "
		"pcr16sha256, pcr17sha256, pcr18sha256, pcr19sha256, "
		"pcr20sha256, pcr21sha256, pcr22sha256, pcr23sha256 "
		"from attestlog where hostname = '%s' order by id",
		hostname);
	rc = SQ_Query(attestLogResult,
		      mysql, query);
    }
    MYSQL_ROW attestLogRow = NULL; 
    if (rc == 0) {
	rc = SQ_FetchRow(&attestLogRow,
			 0,			/* get last row */
			 *attestLogResult);
    }
    if (rc == 0) {
	if (attestLogId != NULL) {
	    if (vverbose) printf("SQ_GetAttestLogPCRs: attestLogId %s\n", attestLogRow[0]);
	    if (attestLogRow[0] != NULL) {
		*attestLogId = malloc(strlen(attestLogRow[0]) +1);	/* freed by caller */
		if (*attestLogId == NULL) {
		    ; /* FIXME this should never fail because the Id is small.  Better to convert to
			 int and use that */
		}
		else {
		    strcpy(*attestLogId, attestLogRow[0]);
		}
	    }
	    else {
		*attestLogId = NULL;
	    }
	}
	unsigned int pcrNum;
	for (pcrNum = 0 ; pcrNum < TPM_NUM_PCR ; pcrNum++) {
	    pcrsSha1[pcrNum] = attestLogRow[1 + pcrNum];
	    pcrsSha256[pcrNum] = attestLogRow[1 + TPM_NUM_PCR + pcrNum];
	}
	for (pcrNum = 0 ; pcrNum < TPM_NUM_PCR ; pcrNum++) {
	    if (vverbose) printf("SQ_GetAttestLogPCRs: SHA1   PCR%02u %s \n",
				 pcrNum, pcrsSha1[pcrNum]);
	}
	for (pcrNum = 0 ; pcrNum < TPM_NUM_PCR ; pcrNum++) {
	    if (vverbose) printf("SQ_GetAttestLogPCRs: SHA256 PCR%02u %s \n",
				 pcrNum, pcrsSha256[pcrNum]);
	}
    }
    return rc;
}

/* SQ_GetPreviousPcrs() gets the previous row from the attestlog table for this hostname and
   boottime (if not NULL).

   A failure return code means that this is the first time for the machine (and boot cycle).
*/

uint32_t SQ_GetPreviousPcrs(const char *previousPcrsSha1[],
			    const char *previousPcrsSha256[],
			    MYSQL_RES **previousPcrsResult,	/* freed by caller */
			    MYSQL *mysql,
			    const char *hostname,
			    const char *boottime)
{
    uint32_t	rc = 0;
    const char *pcralg = NULL;
    char 	query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	if (previousPcrsSha256 != NULL) {	/* use SHA-256 for TPM 2.0 */
	    pcralg = "pcr00sha256";
	}
	else {					/* use SHA-1 for TPM 1.2 */
	    pcralg = "pcr00sha1";
	}
    }
    if (rc == 0) {
	if (boottime != NULL) {
	    sprintf(query,
		    "select "
		    "pcr00sha1, pcr01sha1, pcr02sha1, pcr03sha1, "
		    "pcr04sha1, pcr05sha1, pcr06sha1, pcr07sha1, "
		    "pcr08sha1, pcr09sha1, pcr10sha1, pcr11sha1, "
		    "pcr12sha1, pcr13sha1, pcr14sha1, pcr15sha1, "
		    "pcr16sha1, pcr17sha1, pcr18sha1, pcr19sha1, "
		    "pcr20sha1, pcr21sha1, pcr22sha1, pcr23sha1, "
		    "pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, "
		    "pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256, "
		    "pcr08sha256, pcr09sha256, pcr10sha256, pcr11sha256, "
		    "pcr12sha256, pcr13sha256, pcr14sha256, pcr15sha256, "
		    "pcr16sha256, pcr17sha256, pcr18sha256, pcr19sha256, "
		    "pcr20sha256, pcr21sha256, pcr22sha256, pcr23sha256 "
		    "from attestlog where hostname = '%s' "
		    "and %s != 'NULL' "
		    "and boottime = '%s' "
		    "order by id",
		    hostname, pcralg, boottime);
	}
	else {	/* boot time NULL, ignore boottime */
	    sprintf(query,
		    "select "
		    "pcr00sha1, pcr01sha1, pcr02sha1, pcr03sha1, "
		    "pcr04sha1, pcr05sha1, pcr06sha1, pcr07sha1, "
		    "pcr08sha1, pcr09sha1, pcr10sha1, pcr11sha1, "
		    "pcr12sha1, pcr13sha1, pcr14sha1, pcr15sha1, "
		    "pcr16sha1, pcr17sha1, pcr18sha1, pcr19sha1, "
		    "pcr20sha1, pcr21sha1, pcr22sha1, pcr23sha1, "
		    "pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, "
		    "pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256, "
		    "pcr08sha256, pcr09sha256, pcr10sha256, pcr11sha256, "
		    "pcr12sha256, pcr13sha256, pcr14sha256, pcr15sha256, "
		    "pcr16sha256, pcr17sha256, pcr18sha256, pcr19sha256, "
		    "pcr20sha256, pcr21sha256, pcr22sha256, pcr23sha256 "
		    "from attestlog where hostname = '%s' "
		    "and %s != 'NULL' "
		    "order by id",
		    hostname, pcralg);
	}
	rc = SQ_Query(previousPcrsResult,
		      mysql, query);
    }
    MYSQL_ROW attestLogRow = NULL; 
    if (rc == 0) {
	rc = SQ_FetchRow(&attestLogRow,
			 0,		/* offset to previous row */
			 *previousPcrsResult);
    }
    if (rc == 0) {
	unsigned int pcrNum;
	for (pcrNum = 0 ; pcrNum < TPM_NUM_PCR ; pcrNum++) {
	    previousPcrsSha1[pcrNum] = attestLogRow[pcrNum];
	    if (previousPcrsSha256 != NULL) {			/* TPM 2.0 only */
		previousPcrsSha256[pcrNum] = attestLogRow[pcrNum + TPM_NUM_PCR];
	    }
	}
	for (pcrNum = 0 ; pcrNum < TPM_NUM_PCR ; pcrNum++) {
	    if (vverbose) printf("SQ_GetPreviousPcrs: SHA1   PCR%02u %s \n",
				 pcrNum, previousPcrsSha1[pcrNum]);
	}
	for (pcrNum = 0 ; (previousPcrsSha256 != NULL) && (pcrNum < TPM_NUM_PCR) ; pcrNum++) {
	    if (vverbose) printf("SQ_GetPreviousPcrs: SHA256 PCR%02u %s \n",
				 pcrNum, previousPcrsSha256[pcrNum]);
	}
    }
    else {
	if (vverbose) printf("SQ_GetPreviousPcrs: No previous PCRs\n");
	printf("INFO: SQ_GetPreviousPcrs: Not necessarily an error\n");
    }
    return rc;
}

/* SQ_GetFirstPcrs() gets the PCR while list form the machines DB for this hostname.

   Return code failure if no first PCRs white list.
*/

uint32_t SQ_GetFirstPcrs(const char *firstPcrsSha1String[],
			 const char *firstPcrsSha256String[],
			 MYSQL_RES **firstPcrsResult,	/* freed by caller */
			 MYSQL *mysql,
			 const char *hostname)
{
    uint32_t	rc = 0;
    char 	query[QUERY_LENGTH_MAX];

    if (rc == 0) {
	sprintf(query,
		"select "
		"pcr00sha1, pcr01sha1, pcr02sha1, pcr03sha1, "
		"pcr04sha1, pcr05sha1, pcr06sha1, pcr07sha1, "
		"pcr08sha1, pcr09sha1, pcr10sha1, pcr11sha1, "
		"pcr12sha1, pcr13sha1, pcr14sha1, pcr15sha1, "
		"pcr16sha1, pcr17sha1, pcr18sha1, pcr19sha1, "
		"pcr20sha1, pcr21sha1, pcr22sha1, pcr23sha1, "
		"pcr00sha256, pcr01sha256, pcr02sha256, pcr03sha256, "
		"pcr04sha256, pcr05sha256, pcr06sha256, pcr07sha256, "
		"pcr08sha256, pcr09sha256, pcr10sha256, pcr11sha256, "
		"pcr12sha256, pcr13sha256, pcr14sha256, pcr15sha256, "
		"pcr16sha256, pcr17sha256, pcr18sha256, pcr19sha256, "
		"pcr20sha256, pcr21sha256, pcr22sha256, pcr23sha256 "
		"from machines where hostname = '%s' order by id",
		hostname);
	rc = SQ_Query(firstPcrsResult,
		      mysql, query);
    }
    MYSQL_ROW attestLogRow = NULL;
    /* server error if this fails */
    if (rc == 0) {
	rc = SQ_FetchRow(&attestLogRow,
			 0,		/* offset to first row */
			 *firstPcrsResult);
    }
    if (rc == 0) {
	unsigned int pcrNum;
	for (pcrNum = 0 ; pcrNum < TPM_NUM_PCR ; pcrNum++) {
	    if (firstPcrsSha1String != NULL) {
		firstPcrsSha1String[pcrNum] = attestLogRow[pcrNum];
	    }
	    if (firstPcrsSha256String != NULL) {
		firstPcrsSha256String[pcrNum] = attestLogRow[pcrNum + TPM_NUM_PCR];
	    }
	}
	for (pcrNum = 0 ; (firstPcrsSha1String != NULL) && (pcrNum < TPM_NUM_PCR) ; pcrNum++) {
	    if (vverbose) printf("SQ_GetFirstPcrs: SHA1   PCR%02u %s \n",
				 pcrNum, firstPcrsSha1String[pcrNum]);
	}
	for (pcrNum = 0 ; (firstPcrsSha256String != NULL) && (pcrNum < TPM_NUM_PCR) ; pcrNum++) {
	    if (vverbose) printf("SQ_GetFirstPcrs: SHA256 PCR%02u %s \n",
				 pcrNum, firstPcrsSha256String[pcrNum]);
	}
    }
    else {
	if (vverbose) printf("SQ_GetFirstPcrs: No first PCRs\n");
	printf("INFO: SQ_GetFirstPcrs: Not necessarily an error\n");
    }
    return rc;
}

