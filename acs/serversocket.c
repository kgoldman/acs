/********************************************************************************/
/*                                                                              */
/*	TPM 2.0 Attestation - Server Socket Transmit and Receive Utilities	*/
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: serversocket.c 1074 2017-09-12 19:09:40Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017.					*/
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

/* Environment variables are:
           
   ACS_PORT - the client and server socket port number
*/

/* arbitrary maximum command size, to avoid resource exhaustion */

#define COMMAND_MAX 100000000

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/time.h>

#include "commonerror.h"

#include "serversocket.h"

/*
  local prototypes
*/

static uint32_t Socket_ReadBytes(int connection_fd,
				 unsigned char *buffer,
				 size_t nbytes);
static uint32_t Socket_WriteBytes(int connection_fd,
				  const unsigned char *buffer,
				  size_t bufferLength);
/*
  global variables
*/

extern int vverbose;
extern int verbose;

const char 		*port_str;    /* command/response server port
					 port number for TCP/IP
					 domain file name for Unix domain socket */


/* Socket_Init() opens a TCP Server socket given the provided parameters. Sets it into
   listening mode so connections can be accepted.

   The parameters are set through environment variables:

   ACS_PORT: the server port
*/

uint32_t Socket_Init(int *sock_fd)
{
    uint32_t          	rc = 0;
    int                 irc;
    short               port;           /* TCP/IP port */
    int                 domain = AF_INET;
    struct sockaddr_in  serv_addr;
    int                 opt;

    if (vverbose) printf("Socket_Init:\n");
    /* get the socket port number as a string */
    if (rc == 0) {
        port_str = getenv("ACS_PORT");
        if (port_str == NULL) {
            printf("ERROR: Socket_Init: ACS_PORT environment variable not set\n");
            rc = 1;
        }
    }
    /* port number as short int */
    if (rc == 0) {
        irc = sscanf(port_str, "%hu", &port);
        if (irc != 1) {
            printf("ERROR: Socket_Init: ACS_PORT environment variable invalid\n");
            rc = 1;
        }
    }
    /* create a socket */
    if (rc == 0) {
        if (vverbose) printf(" Socket_Init: Port %s\n", port_str);
        *sock_fd = socket(domain, SOCK_STREAM, 0);      /* socket */
        if (*sock_fd == -1) {
            printf("ERROR: Socket_Init: server socket() %d %s\n",
                   errno, strerror(errno));
            rc = 1;
        }
    }
    if (rc == 0) {
        memset((char *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;                 /* Internet socket */
        serv_addr.sin_port = htons(port);               /* host to network byte order for short */
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  /* host to network byte order for long */
        opt = 1;
        /* Set SO_REUSEADDR before calling bind() for servers that bind to a fixed port number. */
        irc = setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (irc != 0) {
            printf("ERROR: Socket_Init: server setsockopt() %d %s\n",
                   errno, strerror(errno));
            rc = 1;
        }
    }
    /* bind the (local) server port name to the socket */
    if (rc == 0) {
        irc = bind(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (irc != 0) {
            close(*sock_fd);
            *sock_fd = -1;
            printf("ERROR: Socket_Init: server bind() %d %s\n",
                   errno, strerror(errno));
            rc = 1;
        }
    }
    /* listen for a connection to the socket */
    if (rc == 0) {
        irc = listen(*sock_fd, SOMAXCONN);
        if (irc != 0) {
            close(*sock_fd);
            *sock_fd = -1;
            printf("ERROR: Socket_Init: server listen() %d %s\n",
                   errno, strerror(errno));
            rc = 1;
        }
    }
    return rc;
}

/* Socket_Connect() establishes a connection between the server and the client
   
   This is the Unix platform dependent socket version.
*/

uint32_t Socket_Connect(int *connection_fd,     /* read/write file descriptor */
			int sock_fd)
{
    uint32_t          	rc = 0;
    socklen_t           cli_len;
    struct sockaddr_in  cli_addr;       /* Internet version of sockaddr */

    if (verbose) printf("Socket_Connect: Waiting for connections on port %s\n", port_str);
        
    cli_len = sizeof(cli_addr);
    /* block until connection from client */
    if (verbose) printf("Socket_Connect: Accepting connection from port %s ...\n", port_str);
    *connection_fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (*connection_fd < 0) {
	printf("ERROR: Socket_Connect: accept() %d %s\n", errno, strerror(errno));
	rc = ASE_ACCEPT;
    }
    return rc;
}

/* Socket_Read() reads a command packet from the client.  The packet is preceded by a 4-byte length
   in network byte order.

   Puts the result in the allocated 'buffer', which must be freed by the caller.

   On success, 'bufferLength' is the number of bytes in the buffer  

   This function is intended to be platform independent.

   Returns:

   0 success
   1 server error
   2 client error
*/

uint32_t Socket_Read(int connection_fd,        	/* read/write file descriptor */
		     unsigned char **buffer,   	/* output: command stream */
		     uint32_t *bufferLength)	/* output: command stream length */
{       
    uint32_t          rc = 0;
    
    /* test that connection is open to read */
    if (rc == 0) {
        if (connection_fd < 0) {
            printf("ERROR: Socket_Read: connection not open, fd %d\n", connection_fd);
            rc = ASE_ACCEPT;	/* server error */
        }
    }
    /* read the length prepended to the packet */
    if (rc == 0) {
	uint32_t bufferLengthNbo;
        rc = Socket_ReadBytes(connection_fd, (unsigned char *)&bufferLengthNbo, sizeof(uint32_t));
	*bufferLength = ntohl(bufferLengthNbo);
    }
    if (rc == 0) {
	if (*bufferLength > COMMAND_MAX) {
            printf("ERROR: Socket_Read: length %u too large\n", *bufferLength);
            rc = ACE_PACKET_LENGTH;	/* client error */
	}
    }
    /* allocate memory for the buffer */
    if (rc == 0) {
	*buffer = malloc(*bufferLength);
	if (*buffer == NULL) {
            printf("ERROR: Socket_Read: mallocing %u bytes\n", *bufferLength);
	    rc = ASE_OUT_OF_MEMORY;	/* server error */
	}
    }
    /* read the rest of the command */
    if (rc == 0) {
        rc = Socket_ReadBytes(connection_fd,
                              *buffer,
                              *bufferLength);
    }
#if 0
    if (rc == 0) {
        TPM_PrintAll(" Socket_Read:", *buffer, *bufferLength);
    }
#endif
    return rc;
}

/* Socket_ReadBytes() reads nbytes from connection_fd and puts them in buffer.

   The buffer has already been checked for sufficient size.

   This is the Unix platform dependent socket version.

   Returns:

   0 success
   1 server error
   2 client error
*/

static uint32_t Socket_ReadBytes(int connection_fd,    /* read/write file descriptor */
				 unsigned char *buffer,
				 size_t nbytes)
{
    uint32_t rc = 0;
    ssize_t nread = 0;
    size_t nleft = nbytes;

    if (vverbose) printf("  Socket_ReadBytes: Reading %lu bytes\n", (unsigned long)nbytes);
    /* read() is unspecified with nbytes too large */
    if (rc == 0) {
        if (nleft > SSIZE_MAX) {	/* should never occur */
            printf("ERROR: Socket_ReadBytes: size %lu too large\n", (unsigned long)nbytes);
            rc = ACE_PACKET_LENGTH;
        }
    }
    while ((rc == 0) && (nleft > 0)) {
        nread = read(connection_fd, buffer, nleft);
        if (nread > 0) {
            nleft -= nread;
            buffer += nread;
        }           
        else if (nread < 0) {       /* client error */
            printf("ERROR: Socket_ReadBytes: read() error %d %s\n", errno, strerror(errno));
            rc = ACE_READ;
        }
        else if (nread == 0) {          /* EOF, client error */
            printf("ERROR: Socket_ReadBytes: read EOF, read %lu bytes\n",
                   (unsigned long)(nbytes - nleft));
            rc = ACE_READ;
        }
    }
    return rc;
}

/* Socket_Write() writes a response packet to the client.  The packet is preceded by a 4-byte length
   in network byte order.

   This function is intended to be platform independent.

   Returns:

   0 success
   1 server error
   2 client error
*/

uint32_t Socket_Write(int connection_fd,       /* read/write file descriptor */
		      const unsigned char *buffer,
		      size_t bufferLength)
{
    uint32_t  rc = 0;

    /* test that connection is open to write */
    if (rc == 0) {
        if (connection_fd < 0) {
            printf("ERROR: Socket_Write: connection not open, fd %d\n",
                   connection_fd);
            rc = ASE_ACCEPT;
        }
    }
    /* prepend the length to the packet */
    if (rc == 0) {
	uint32_t bufferLengthNbo = htonl(bufferLength);
	rc = Socket_WriteBytes(connection_fd, (unsigned char *)&bufferLengthNbo, sizeof(uint32_t));
    }
    /* write the buffer */
    if (rc == 0) {
	rc = Socket_WriteBytes(connection_fd, buffer, bufferLength);
    }
    return rc;
}

/* Socket_WriteBytes() writes 'buffer_length' bytes to the host.
   
   This is the Unix platform dependent socket version.

   Returns:

   0 success
   1 server error
   2 client error
*/

static uint32_t Socket_WriteBytes(int connection_fd,       /* read/write file descriptor */
				  const unsigned char *buffer,
				  size_t buffer_length)
{       
    uint32_t  	rc = 0;
    ssize_t     nwritten = 0;
    
#if 0
    if (rc == 0) {
        TPM_PrintAll("Socket_WriteBytes:", buffer, buffer_length);
    }
#endif
    /* write() is unspecified with buffer_length too large */
    if (rc == 0) {
        if (buffer_length > SSIZE_MAX) {	/* should never occur */
            printf("ERROR: Socket_WriteBytes: size %lu too large\n", (unsigned long)buffer_length);
            rc = ASE_PACKET_LENGTH	;
        }
    }
    while ((rc == 0) && (buffer_length > 0)) {
        nwritten = write(connection_fd, buffer, buffer_length);
        if (nwritten >= 0) {
            buffer_length -= nwritten;
            buffer += nwritten;
        }
        else {
            printf("ERROR: Socket_Write: write() %d %s\n", errno, strerror(errno));
            rc = ACE_WRITE;       /* client error */
        }
    }
    return rc;
}

/* Socket_Disconnect() breaks the connection between the server and the host client.

   If connection_fd is <0, the command is a noop.  Sets connection_fd to -1 after the close.

   This is the Unix platform dependent socket version.
*/

void Socket_Disconnect(int *connection_fd)
{
    /* close the connection to the client */
    if (*connection_fd >= 0) {
	close(*connection_fd);
	*connection_fd = -1;     /* mark the connection closed */
    }
    return;
}


