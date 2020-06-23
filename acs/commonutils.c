/********************************************************************************/
/*										*/
/*	TPM 2.0 Attestation - Common Client / Server Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commonutils.c 1607 2020-04-28 21:35:05Z kgoldman $		*/
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

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#include "config.h"
#include "commonerror.h"

#include "commonutils.h"

/* Array_Print() converts a binary array 'data' of 'len' to a string.

   For debug:

   If name is not NULL, prints the name first.
   If string is NULL, prints the data to stdout.  If string is not NULL, prints data to string.
   If string is NULL and newlines is TRUE, prints a newline after every 16 characters and at the end
*/

void Array_Print(char *string, const char *name, int newlines,
		const unsigned char *data, unsigned int len)
{
    unsigned int i = 0;
    if (name != NULL) {
	printf("%s \n", name);
    }
    if (string != NULL) {	/* handle the len = 0 case */
	string[0] = '\0';
    }
    while (i < len) {
	if (string == NULL) {
	    printf("%02x ",data[i]);
	}
	else {
	    sprintf(string, "%02x",data[i]);
	    string += 2;
	}
	i++;
	if (0 == (i & 0xf)) {
	    if ((string == NULL) && newlines) {
		printf("\n");
	    }
	}
    }
    if ((string == NULL) && newlines) {
	printf("\n");
    }
    return;
}

/* Array_PrintMalloc() allocates a buffer, then prints the array in hexascii to the buffer.

 */

uint32_t Array_PrintMalloc(char **string,		/* freed by caller */
			   const uint8_t *data,
			   uint32_t len)
{
    uint32_t 	rc = 0;
    if (rc == 0) {
	*string = malloc((len * 2) + 1);
	if (*string == NULL) {
	    printf("ERROR: Array_PrintMalloc: could not malloc %u bytes\n", (len * 2) + 1);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	Array_Print(*string, NULL, FALSE, data, len);
    }
    return rc;
}

/* Array_Scan() converts a hexascii string to a binary array */

/* FIXME use tssprint.c function */

uint32_t Array_Scan(unsigned char **data,	/* output binary, freed by caller */
		    size_t *len,
		    const char *string)		/* input string */
{
    uint32_t rc = 0;
    size_t strLength;
    
    if (rc == 0) {
	strLength = strlen(string);
	if ((strLength %2) != 0) {
	    printf("ERROR: Array_Scan: number of bytes %lu is not even\n",
		   (unsigned long)strLength);
	    rc = ACE_HEXASCII;
	}
    }
    if (rc == 0) {
	*len = strlen(string) / 2;	/* safe because already tested for even number of bytes */
	*data = malloc((*len) + 8);	/* add bytes at end because scanf uses int */
	if (*data == NULL) {
	    printf("ERROR: Array_Scan: could not malloc %u bytes\n", (unsigned int)*len);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	unsigned int i;
	for (i = 0 ; i < *len ; i++) {
	    unsigned int tmpint;
	    int irc = sscanf(string + (2*i), "%2x", &tmpint);
	    *((*data)+i) = tmpint;
	    if (irc != 1) {
		printf("ERROR: Array_Scan: invalid hexascii\n");
		rc = ACE_HEXASCII;
	    }
	}
    }
    return rc;
}

/* Structure_Print() is a general purpose "hexascii print a structure" function.

   It marshals the structure using "marshalFunction", and returns the malloc'ed hexascii
*/

uint32_t Structure_Print(char 			**string,	/* freed by caller */
			 void 			*structure,
			 MarshalFunction_t 	marshalFunction)
{
    uint32_t 	rc = 0;
    uint8_t	*buffer = 0;	/* marshaled binary */
    uint16_t	written;
    
    if (rc == 0) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed by @1 */
				   &written,
				   structure,
				   marshalFunction);
    }
    if (rc == 0) {
	rc = Array_PrintMalloc(string,		/* freed by caller */
			       buffer,
			       written);
    }
    free(buffer);	/* @1 */
    return rc;
}

/* Structure_Scan() is a general purpose "hexascii scan a structure function.

   It converts the hexascii to binary, and then unmarshals to the structure.
*/

uint32_t Structure_Scan(void 			*structure,
		       UnmarshalFunction_t 	unmarshalFunction,
		       const char 		*string)
{
    uint32_t 	rc = 0;
    uint8_t 	*bin = NULL;
    size_t 	binLen;
    
    if (rc == 0) {
	rc = Array_Scan(&bin,		/* freed @1 */
			&binLen,
			string);
    }
    if (rc == 0) {
	uint8_t	*tmpbuf = bin;
	uint32_t ilength = binLen;
	rc = unmarshalFunction(structure, &tmpbuf, &ilength);
    }
    free(bin);		/* @1 */
    return rc;
}

/* makeAkFilenames() assembles the full AK file name (public and private for TPM 2.0), combined for
   TPM 1.2) from a

   [directory path / ] file name [ _ machine name ] base name .bin
*/

uint32_t makeAkFilenames(char 		*akpubFullName,
			 char 		*akprivFullName,
			 size_t 	akFullNameSize,
			 const char 	*akpubFilename,			 
			 const char 	*akprivFilename,
			 const char 	*machineName)
{
    TPM_RC 	rc = 0;
    const char 	*acsDir = NULL;
    size_t 	acsDirLength = 0;
    size_t 	machineNameLength = 0;		/* if NULL */
    
    if (rc == 0) {
	acsDir = getenv("ACS_DIR");	/* remains NULL if not defined */
	/* directory for client persistent files */
	/* check the parameters against the AK full path name */
	acsDirLength = 0;			/* if NULL */
	if (acsDir != NULL) {
	    acsDirLength = strlen(acsDir) +1;	/* +1 for the / */
	}
	machineNameLength = 0;		/* if NULL */
	if (machineName != NULL) {
	    machineNameLength = strlen(machineName) +1;	/* +1 for the underscore */
	}
	size_t fileNameMax = strlen(AK_FILENAME_MAX) + sizeof(".bin");	/* sizeof for the nul */
	if ((acsDirLength + machineNameLength + fileNameMax) > akFullNameSize) {
	    printf("\nERROR: makeAkFilenames: directory name %u + machine name %u too long\n",
		   (unsigned int)acsDirLength, (unsigned int)machineNameLength);
	    rc = ACE_FILE_NAME;
	}
    }
    if (rc == 0) {
	/* Build up the AK filenames. If machine name is specified, it is appended to the default
	   file name. */
	if ((acsDir == NULL) && (machineName == NULL)) {
	    if (akpubFullName != NULL) {
		sprintf(akpubFullName, "%s.bin", akpubFilename);
	    }
	    sprintf(akprivFullName, "%s.bin", akprivFilename);
	}
	else if ((acsDir == NULL) && (machineName != NULL)) {
	    if (akpubFullName != NULL) {
		sprintf(akpubFullName, "%s_%s.bin", akpubFilename, machineName);
	    }
	    sprintf(akprivFullName, "%s_%s.bin", akprivFilename, machineName);
	}
	else if ((acsDir != NULL) && (machineName == NULL)) {
	    if (akpubFullName != NULL) {
		sprintf(akpubFullName, "%s/%s.bin", acsDir, akpubFilename);
	    }
	    sprintf(akprivFullName, "%s/%s.bin", acsDir, akprivFilename);
	}
	else if ((acsDir != NULL) && (machineName != NULL)) {
	    if (akpubFullName != NULL) {
		sprintf(akpubFullName, "%s/%s_%s.bin", acsDir, akpubFilename, machineName);
	    }
	    sprintf(akprivFullName, "%s/%s_%s.bin", acsDir, akprivFilename, machineName);
	}
	/* printf("%s\n%s\n", akpubFullName, akprivFullName); */
    }
    /* test that the directory is writable */
    char *tmpFilename = NULL;		/* freed @1 */
    if (rc == 0) {
	tmpFilename = malloc(akFullNameSize);
	if (tmpFilename == NULL) {
	    printf("\nERROR:  makeAkFilenames: directory name %u + machine name %u too long\n",
		   (unsigned int)acsDirLength, (unsigned int)machineNameLength);
	    rc = ACE_ALLOC;		
	}
    }
    if (rc == 0) {
	if (acsDir == NULL) {
	    sprintf(tmpFilename, "tmp.bin");
	}
	else {
	    sprintf(tmpFilename, "%s/tmp.bin", acsDir);
	}
	FILE *file = fopen(tmpFilename, "wb");		/* closed @2 */
	if (file == NULL) {
	    printf("\nERROR:  makeAkFilenames: file %s cannot be opened for write\n",
		   tmpFilename);
	    rc = ACE_FILE_NAME;
	}
	if (file != NULL) {
	    fclose(file);		/* @2 */
	}
	remove(tmpFilename);
    }
    free(tmpFilename);			/* @1 */
    return rc;
}
