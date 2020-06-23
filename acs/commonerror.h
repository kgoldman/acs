/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common Error Codes	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commonerror.h 1607 2020-04-28 21:35:05Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016 = 2020					*/
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

#ifndef COMMONERROR_H
#define COMMONERROR_H

/* client errors */

#define ACE_ERROR_FIRST		0x90000000
#define ACE_ERROR_LAST		0x9fffffff

#define ACE_PACKET_LENGTH	0x90000001	/* client packet length too large */
#define ACE_READ		0x90000002	/* client data read error */
#define ACE_WRITE		0x90000003	/* client data write error */
#define ACE_JSON_COMMAND	0x90000004	/* client json command parse error */
#define ACE_JSON_KEY		0x90000005	/* json missing key */
#define ACE_HEXASCII		0x90000006	/* client malformed hexascii */
#define ACE_INVALID_CERT 	0x90000007	/* client certificate is invalid */
#define ACE_MISMATCH_CERT	0x90000008	/* client certificate mismatch */
#define ACE_TPM20_UNSUPPORTED	0x90000009	/* client is TPM 2.0, but server does not support it */
#define ACE_TPM12_UNSUPPORTED	0x9000000a	/* client is TPM 1.2, but server does not support it */
#define ACE_ALLOC		0x9000000b	/* client memory allocation failed */

#define ACE_QUOTE_SIGNATURE	0x90000010	/* client quote signature invalid */
#define ACE_QUOTE_MISSING	0x90000011	/* client quote has not been sent */
#define ACE_PCR_LENGTH		0x90000012	/* client PCR length incorrect */
#define ACE_PCR_BANK		0x90000013	/* client PCR bank incorrect */
#define ACE_PCR_SELECT		0x90000014	/* client PCR select incorrect */
#define ACE_PCR_VALUE		0x90000015	/* client PCRs values incorrect */
#define ACE_PCR_MISSING		0x90000016	/* client PCRs missing in DB */
#define ACE_DIGEST_LENGTH	0x90000017	/* client digest length is incorrect */
#define ACE_DIGEST_VALUE	0x90000018	/* client digest value is incorrect */
#define ACE_NONCE_LENGTH	0x90000019	/* client nonce length is incorrect */
#define ACE_NONCE_VALUE		0x9000001a	/* client nonce value is incorrect */
#define ACE_NONCE_MISSING	0x9000001b	/* client nonce value missing */
#define ACE_NONCE_USED		0x9000001c	/* client nonce value has already been used */
#define ACE_PCR_INDEX		0x9000001d	/* client invalid PCR index */
#define ACE_BAD_ALGORITHM	0x9000001e	/* client algorithm not supported */
#define ACE_BAD_BLOB		0x9000001f	/* client received malformed blob */

#define ACE_EVENT		0x90000020	/* client event invalid */
#define ACE_NO_ENROLL_REQ	0x90000021	/* client hostname missing enroll request */
#define ACE_ENROLLED		0x90000022	/* client hostname already enrolled */
#define ACE_NOT_ENROLLED	0x90000023	/* client hostname not enrolled */
#define ACE_INVALID_KEY		0x90000024	/* client attestation key invalid */
#define ACE_OSSL_AES		0x90000025	/* client decrypt error */
#define ACE_UNKNOWN_CMD		0x90000026	/* client unknown command */
#define ACE_BAD_JSON		0x90000027	/* client sent malformed json */
#define ACE_OUT_OF_MEMORY	0x90000028	/* client out of memory */
#define ACE_FILE_NAME		0x80000029	/* client bad file name */
#define ACE_FILE_OPEN		0x9000002a	/* client file open failure */
#define ACE_FILE_READ		0x9000002b	/* client file read failure */
#define ACE_OSSL_X509		0x9000002c	/* openssl X509 failure */
#define ACE_OSSL_ECC		0x9000002e	/* openssl ECC failure */
#define ACE_OSSL_RAND		0x9000002f	/* openssl random number failure */

/* server errors, likely fatal */

#define ASE_ERROR_FIRST		0x80000000
#define ASE_ERROR_LAST		0x8fffffff

#define ASE_ACCEPT		0x80000001	/* client accept failed */
#define ASE_OUT_OF_MEMORY	0x80000002	/* server out of memory */
#define ASE_PACKET_LENGTH	0x80000003	/* server packet length too large */
#define ASE_SOCKET_ERROR	0x80000004	/* server socket error */

#define ASE_OSSL_BIO		0x80000010	/* openssl BIO failure */
#define ASE_OSSL_PEM		0x80000011	/* openssl PEM failure */
#define ASE_OSSL_X509		0x80000012	/* openssl X509 failure */
#define ASE_OSSL_NID		0x80000013	/* openssl NID failure */
#define ASE_OSSL_BN		0x80000014	/* openssl BN failure */
#define ASE_OSSL_RSA		0x80000015	/* openssl RSA failure */
#define ASE_OSSL_AES		0x80000016	/* openssl AES failure */
#define ASE_OSSL_DIGEST		0x80000017	/* openssl Digest failure */
#define ASE_OSSL_RAND		0x80000018	/* openssl random number failure */

#define ASE_JSON_SERIALIZE	0x80000030	/* server could not serialize response */
#define ASE_NO_RESPONSE		0x80000031	/* server could not construct response */

#define ASE_SQL_CONNECT		0x80000040	/* server could not connect to database */
#define ASE_SQL_QUERY 		0x80000041	/* server database query failed */
#define ASE_SQL_ERROR		0x80000042	/* error in SQL query */

#define ASE_FILE_READ		0x80000050	/* server file read failure */

#define ASE_BAD_ALG		0x80000040	/* server unsupported algorithm */

#define ASE_NULL_VALUE		0x80000050	/* a value is unexpectedly NULL */


#endif
