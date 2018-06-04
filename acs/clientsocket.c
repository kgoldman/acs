/********************************************************************************/
/*										*/
/*	TPM 2.0 Attestation - Client Socket Transmit and Receive Utilities	*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientsocket.c 757 2016-09-26 20:02:41Z kgoldman $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>

#include "clientsocket.h"

/* local prototypes */

static uint32_t Socket_SendBytes(int sock_fd, const uint8_t *buffer, size_t length);
static uint32_t Socket_ReceiveBytes(int sock_fd, uint8_t *buffer, uint32_t nbytes);

extern int vverbose;
extern int verbose;

/* Socket_Process() opens a socket, sends the command, receives the response, and closes the
   socket.

*/

uint32_t Socket_Process(uint8_t **rspBuffer,	/* freed by caller */
			uint32_t *rspLength,
			const char *hostname,
			short port,
			uint8_t *cmdBuffer,
			uint32_t cmdLength)
{
    uint32_t rc = 0;
    int sock_fd = -1;		/* error value, for close noop */
    if (rc == 0) {
	rc = Socket_Open(&sock_fd, hostname, port);
    }
    if (rc == 0) {
	rc = Socket_Send(sock_fd, cmdBuffer, cmdLength);
    }
    if (rc == 0) {
	rc = Socket_Receive(sock_fd, rspBuffer, rspLength);	/* freed by caller */
    }
    Socket_Close(sock_fd);
    return rc;
}

/* Socket_Open() opens the socket to the server at hostname
 */

uint32_t Socket_Open(int *sock_fd,
		     const char *hostname,
		     short port)
{
    const char 		*serverName = hostname;
    struct sockaddr_in 	serv_addr;
    struct hostent 	*host = NULL;
    
    if (vverbose) printf("Socket_Open: server %s port %hu\n", serverName, port); 
    if ((*sock_fd = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
	printf("ERROR: Socket_Open: client socket: %d %s\n",
	       errno,strerror(errno));
	return -1;
    }
    /* establish the connection to server */
    memset((char *)&serv_addr,0x0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    /* first assume server is dotted decimal number and call inet_addr */
    if ((int)(serv_addr.sin_addr.s_addr = inet_addr(serverName)) == -1) {
	/* if inet_addr fails, assume server is a name and call gethostbyname to look it up */
	if ((host = gethostbyname(serverName)) == NULL) {	/* if gethostbyname also fails */
	    printf("ERROR: Socket_Open: server name error, name %s\n", serverName);
	    return -1;
	}
	serv_addr.sin_family = host->h_addrtype;
	memcpy(&serv_addr.sin_addr, host->h_addr, host->h_length);
    }
    else {
	/*  	printf("Socket_Open: server address: %s\n", serverName); */
    }
    if (connect(*sock_fd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
	printf("ERROR: Socket_Open: Error on connect to %s:%u\n",
			       serverName, port);
	if (vverbose) printf("Socket_Open: client connect: error %d %s\n",
			       errno,strerror(errno));
	return -1;
    }
    return 0;
}

/* Socket_Send() sends the command packet over the socket.

   The packet is of the form:

   uint32_t length
   command packet

   Returns an error if the socket send fails.
*/

uint32_t Socket_Send(int sock_fd,
			 const uint8_t *buffer, uint32_t length)
{
    uint32_t rc = 0;

    if (vverbose) printf("Socket_Send: length %u\n", length); 
#if 0
    if ((rc == 0) && vverbose) {
	TPM_PrintAll("Socket_Send",
		     buffer, length);
    }
#endif
    if (rc == 0) {
	uint32_t lengthNbo = htonl(length);
	rc = Socket_SendBytes(sock_fd, (uint8_t *)&lengthNbo, sizeof(uint32_t));
    }
    if (rc == 0) {
	rc = Socket_SendBytes(sock_fd, buffer, length);
    }
    return rc;
}

/* Socket_SendBytes() sends the buffer over the socket.
 */

static uint32_t Socket_SendBytes(int sock_fd, const uint8_t *buffer, size_t length)
{
    uint32_t rc = 0;
    int nwritten = 0;
    size_t nleft = 0;
    unsigned int offset = 0;

    nleft = length;
    while (nleft > 0) {
	nwritten = write(sock_fd, &buffer[offset], nleft);
	if (nwritten < 0) {        /* error */
	    printf("ERROR: Socket_SendBytes: write error %d\n", (int)nwritten);
	    return -1;
	}
	nleft -= nwritten;
	offset += nwritten;
    }
    return rc;
}

/* Socket_Receive() reads a response packet from the socket.  It reads the 4 byte prepended
   length, mallocs buffer, and reads the remaining bytes into buffer.

   The packet is of the form:

   uint32_t length
   response packet
*/

uint32_t Socket_Receive(int sock_fd, uint8_t **buffer,	/* freed by caller */
			    uint32_t *length)
{
    uint32_t 	rc = 0;
    uint32_t 	responseLength = 0;
    
    /* read the prepended length */
    if (rc == 0) {
	uint32_t responseLengthNbo;
	rc = Socket_ReceiveBytes(sock_fd, (uint8_t *)&responseLengthNbo, sizeof(uint32_t));
	responseLength = ntohl(responseLengthNbo);
    }
    if (rc == 0) {
	if (vverbose) printf("Socket_Receive: responseLength %u\n", responseLength ); 
	*buffer = malloc(responseLength);
	if (*buffer == NULL) {
	    return -1;
	}
    }
    /* read the rest of the packet */
    if (rc == 0) {
	rc = Socket_ReceiveBytes(sock_fd,
				     *buffer,
				     responseLength);
    }
#if 0
    if ((rc == 0) && tssVverbose) {
	TPM_PrintAll("Socket_ReceiveCommand",
		     buffer, responseSize);
    }
#endif
    *length = responseLength;
    return rc;
}

/* Socket_ReceiveBytes() reads nbytes from socket sock_fd and put them in buffer */

static uint32_t Socket_ReceiveBytes(int sock_fd,
					uint8_t *buffer,  
					uint32_t nbytes)
{
    int nread = 0;
    int nleft = 0;

    nleft = nbytes;
    while (nleft > 0) {
	nread = read(sock_fd, buffer, nleft);
	if (nread <= 0) {       /* error */
	    printf("ERROR: Socket_ReceiveBytes: read error %d\n", nread);
	    return -1;
	}
	else if (nread == 0) {  /* EOF */
	    printf("ERROR: Socket_ReceiveBytes: read EOF\n");
	    return -1;
	}
	nleft -= nread;
	buffer += nread;
    }
    return 0;
}

/* Socket_Close() closes the socket.

   If sock_fd is -1, the socket was not opened and this function is a noop
*/

uint32_t Socket_Close(int sock_fd)
{
    uint32_t 	rc = 0;

    if (sock_fd != -1) {
	if (close(sock_fd) != 0) {
	    printf("ERROR: Socket_Close: close error\n");
	    rc = -1;
	}
    }
    return rc;
}
