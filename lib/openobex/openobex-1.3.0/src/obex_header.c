/*********************************************************************
 *                
 * Filename:      obex_header.c
 * Version:       0.9
 * Description:   OBEX header releated functions
 * Status:        Stable.
 * Author:        Pontus Fuchs <pontus.fuchs@tactel.se>
 * Created at:    Sun Mar 21 14:00:03 1999
 * CVS ID:        $Id: obex_header.c,v 1.11 2002/11/22 19:06:10 holtmann Exp $
 * 
 *     Copyright (c) 1999-2000 Pontus Fuchs, All Rights Reserved.
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>

#include "obex_main.h"
#include "obex_header.h"

/*
 * Function insert_uint_header (buf, identifier, value)
 *
 *    Insert a four byte unsigned integer in network byte order
 *    identifier if the header ID which is supposed to consist of
 *    both the header enconding and type
 */
int insert_uint_header(GNetBuf *msg, uint8_t identifier, uint32_t value)
{
	struct obex_uint_hdr *hdr;

	DEBUG(4, "\n");
	obex_return_val_if_fail(msg != NULL, -1);

	hdr = (struct obex_uint_hdr *) g_netbuf_put(msg, 5);

	hdr->hi = identifier;
	hdr->hv = htonl(value);
	
	return 5;
}

/*
 * Function insert_ubyte_header (buf, identifier, value)
 *
 *    Insert a byte unsigned header.
 */
int insert_ubyte_header(GNetBuf *msg, uint8_t identifier, uint8_t value)
{
	struct obex_ubyte_hdr *hdr;

	DEBUG(4, "\n");
	obex_return_val_if_fail(msg != NULL, -1);

	hdr = (struct obex_ubyte_hdr *) g_netbuf_put(msg, 2);

	hdr->hi = identifier;
	hdr->hv = value;
	
	return 2;
}

/*
 * Function insert_unicode_header (buf, opcode, text)
 *
 *    Insert a char string into the buffer
 *
 */
int insert_unicode_header(GNetBuf *msg, uint8_t opcode, 
			const uint8_t *text, int size)
{
	struct obex_unicode_hdr *hdr;

	DEBUG(4, "\n");
	obex_return_val_if_fail(msg != NULL, -1);
	obex_return_val_if_fail(text != NULL, -1);

	hdr = (struct obex_unicode_hdr *) g_netbuf_put(msg, size + 3);

	hdr->hi = opcode;
	hdr->hl = htons((uint16_t)(size + 3));
	memcpy(hdr->hv, text, size);

	return size+3;

}

/*
 * Function insert_byte_stream_header (buf, opcode, stream, size)
 *
 *    Insert a byte stream into the buffer
 *
 */
int insert_byte_stream_header(GNetBuf *msg, uint8_t opcode,
			const uint8_t *stream, int size)
{
	struct obex_byte_stream_hdr *hdr;

	DEBUG(4, "\n");
	obex_return_val_if_fail(msg != NULL, -1);
	obex_return_val_if_fail(stream != NULL, -1);
	
	hdr = (struct obex_byte_stream_hdr *) g_netbuf_put(msg, size+3);
	if (hdr == 0) {
		DEBUG(4, "put failed!\n");
		return 0;
	}

	hdr->hi = opcode;
	hdr->hl = htons(size+3);

	memcpy(hdr->hv, stream, size);
	
	return size+3;
}
