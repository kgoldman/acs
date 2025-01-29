
/********************************************************************************/
/*                                                                              */
/*	TPM 2.0 Attestation - Server Socket Transmit and Receive Utilities	*/
/*                           Written by Chris Engel                             */
/*                                          					*/
/*            $Id: acsPvmTypes.h 1046 2017-07-19 19:39:37Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2017.						*/
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

#ifndef ACSPVMTYPES_H
#define ACSPVMTYPES_H

#define PACKED __attribute__((__packed__))

/*  Attestastion Server Command Enums */

enum AcsPvmCommand
{
    AcsPvmCommandUnused                      = 0x00,    // Not Used
    AcsPvmCommandRetrieveTpmLogSize          = 0x01,
    AcsPvmCommandRetrieveTpmLog              = 0x02,
    AcsPvmCommandGenerateAttestationKeyPair  = 0x03,
    AcsPvmCommandRecoverAttestationKey       = 0x04,
    AcsPvmCommandQuote                       = 0x05,
    AcsPvmCommandReserved                    = 0x06,    // Reserved 0x06-0xFF
};

enum
{
    AcsPvmStructureVersion                   = 1,
    AcsPvmTCGVersionMajor                    = 2,
    AcsPvmTCGVersionMinor                    = 0,
    AcsPvmMaxCommandRequestSize              = 4*1024,
    AcsPvmMaxCommandResponseSize             = 64*1024,
    AcsPvmBootTimeSize                       = 20,
    AcsTpmVendorStringLength                 = 5,
};

typedef enum AcsPvmLogType
{
    AcsLogTypeSRTM                           = 1,
    AcsLogTypeDRTM                           = 2,
} AcsPvmLogType;

enum AcsPvmCommandStatusCodes
{
    AcsPvmStatus_Success                      = 0x00000000,
    AcsPvmStatus_UnknownCommand               = 0x01000000,
    AcsPvmStatus_UnsupportedVersion           = 0x02000000,
    AcsPvmStatus_UnsupportedTCGVersion        = 0x03000000,
    AcsPvmStatus_CommandSpecificFailure       = 0x04000000,
    AcsPvmStatus_ParameterError               = 0x05000000,
    AcsPvmStatus_InvalidSystemState           = 0x06000000,
    AcsPvmStatus_InvalidState                 = 0x07000000,
    AcsPvmStatus_TCGDefinedFailure            = 0x08000000,
    AcsPvmStatus_OperationTimeout             = 0x09000000,
    AcsPvmStatus_Busy                         = 0x0A000000,
    AcsPvmStatus_InvalidAttestationKeys       = 0x0B000000,
    AcsPvmStatus_AccessDenied                 = 0x0C000000,
    AcsPvmStatus_StatusMask                   = 0xFF000000,
};

struct _AcsPvmCommandRequestHeader
{
    uint8_t  version;
    uint8_t  command;
    uint8_t  TCGVersionMajor;
    uint8_t  TCGVersionMinor;
    uint32_t length;
    uint32_t correlator;
} PACKED;
typedef struct _AcsPvmCommandRequestHeader AcsPvmCommandRequestHeader;

struct _AcsPvmCommandRequest
{
    AcsPvmCommandRequestHeader header;
    uint8_t  payLoad[AcsPvmMaxCommandRequestSize-sizeof(AcsPvmCommandRequestHeader)];

} PACKED;
typedef struct _AcsPvmCommandRequest AcsPvmCommandRequest;

struct _AcsPvmCommandResponseHeader
{
    uint32_t status;
    uint32_t length;
    uint32_t correlator;
} PACKED;
typedef struct _AcsPvmCommandResponseHeader AcsPvmCommandResponseHeader;

struct _AcsPvmCommandResponse
{
    AcsPvmCommandResponseHeader header;
    uint8_t  payLoad[AcsPvmMaxCommandResponseSize-sizeof(AcsPvmCommandResponseHeader)];
} PACKED;
typedef struct _AcsPvmCommandResponse AcsPvmCommandResponse;




#endif
