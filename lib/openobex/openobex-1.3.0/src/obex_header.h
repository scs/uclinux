/*********************************************************************
 *                
 *                
 * Filename:      obex_header.h
 * Version:       1.0
 * Description:   
 * Status:        Stable.
 * Author:        Pontus Fuchs <pontus.fuchs@tactel.se>
 * Created at:    Mon Mar  1 10:30:54 1999
 * CVS ID:        $Id: obex_header.h,v 1.7 2002/11/13 19:51:42 zany Exp $
 * 
 *     Copyright (c) 1999, 2000 Pontus Fuchs, All Rights Reserved.
 *     
 *     This library is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU Lesser General Public
 *     License as published by the Free Software Foundation; either
 *     version 2 of the License, or (at your option) any later version.
 *
 *     This library is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *     Lesser General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public
 *     License along with this library; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 *     MA  02111-1307  USA
 *     
 ********************************************************************/
   
#ifndef OBEX_HEADERS_H
#define OBEX_HEADERS_H
 
#include "obex_main.h"

#define OBEX_HI_MASK     0xc0
#define OBEX_UNICODE     0x00
#define OBEX_BYTE_STREAM 0x40
#define OBEX_BYTE        0x80
#define OBEX_INT         0xc0

#ifdef _WIN32
#ifndef PACKED
#define PACKED
#endif
#else
#define PACKED __attribute__((packed))
#endif

/* Common header used by all frames */

#ifdef _WIN32
#pragma pack(1)
#endif /* _WIN32 */
struct obex_common_hdr {
	uint8_t  opcode;
	uint16_t len;
} PACKED;


typedef struct obex_common_hdr obex_common_hdr_t;

/* Connect header */
#ifdef _WIN32
#pragma pack(1)
#endif /* _WIN32 */
struct obex_connect_hdr {
	uint8_t  version;
	uint8_t  flags;
	uint16_t mtu;
} PACKED;
typedef struct obex_connect_hdr obex_connect_hdr_t;

#ifdef _WIN32
#pragma pack(1)
#endif /* _WIN32 */
struct obex_uint_hdr {
	uint8_t  hi;
	uint32_t hv;
} PACKED;

#ifdef _WIN32
#pragma pack(1)
#endif /* _WIN32 */
struct obex_ubyte_hdr {
	uint8_t hi;
	uint8_t hv;
} PACKED;

#ifdef _WIN32
#pragma pack(1)
#endif /* _WIN32 */
struct obex_unicode_hdr {
	uint8_t  hi;
	uint16_t hl;
	uint8_t  hv[0];
} PACKED;

#define obex_byte_stream_hdr obex_unicode_hdr

typedef struct {
	uint8_t identifier;    /* Header ID */
	int  length;         /* Total lenght of header */

	int  val_size;       /* Size of value */
	union {
		int   integer;
		char   *string;
		uint8_t *oct_seq;
	} t;
} obex_header_t;

int insert_uint_header(GNetBuf *msg, uint8_t identifier, uint32_t value);
int insert_ubyte_header(GNetBuf *msg, uint8_t identifier, uint8_t value);
int insert_unicode_header(GNetBuf *msg, uint8_t opcode, const uint8_t *text,
				int size);

int insert_byte_stream_header(GNetBuf *msg, uint8_t opcode, 
			const uint8_t *stream, int size);

int obex_extract_header(GNetBuf *msg, obex_header_t *header);

#endif
