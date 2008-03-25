/*********************************************************************
 *                
 * Filename:      obex_connect.c
 * Version:       0.9
 * Description:   Parse and create connect-command.
 * Status:        Stable
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Wed May  5 11:53:44 1999
 * CVS ID:        $Id: obex_connect.c,v 1.8 2002/11/22 19:06:10 holtmann Exp $
 * 
 *     Copyright (c) 2000 Pontus Fuchs, All Rights Reserved.
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

#include <stdio.h>
#include <string.h>

#include "obex_main.h"
#include "obex_object.h"
#include "obex_header.h"

#include "obex_connect.h"

/*
 * Function obex_insert_connectframe ()
 *
 *    Add the data needed to send/reply to a connect
 *
 */
int obex_insert_connectframe(obex_t *self, obex_object_t *object)
{
	obex_connect_hdr_t *conn_hdr;

	DEBUG(4, "\n");

	object->tx_nonhdr_data = g_netbuf_new(4);
	if(!object->tx_nonhdr_data) 
		return -1;
	conn_hdr = (obex_connect_hdr_t *) object->tx_nonhdr_data->data;
	conn_hdr->version = OBEX_VERSION; 
	conn_hdr->flags = 0x00;              /* Flags */
	conn_hdr->mtu = htons(self->mtu_rx); /* Max packet size */
	g_netbuf_put(object->tx_nonhdr_data, 4);
	return 0;
}

/*
 * Function obex_parse_connect_header ()
 *
 *    Parse a Connect
 *
 */
int obex_parse_connect_header(obex_t *self, GNetBuf *msg)
{
	obex_connect_hdr_t *conn_hdr;
	obex_common_hdr_t *common_hdr;
		
	uint8_t version;
	int flags;
	uint16_t mtu;  /* Maximum send data unit */
	uint8_t opcode;
	uint16_t length;

	DEBUG(4, "\n");

	/* Remember opcode and size for later */
	common_hdr = (obex_common_hdr_t *) msg->data;
	opcode = common_hdr->opcode;
	length = ntohs(common_hdr->len);

	/* Parse beyond 3 bytes only if response is success */
	if( (opcode != (OBEX_RSP_SUCCESS | OBEX_FINAL)) && (opcode != (OBEX_CMD_CONNECT | OBEX_FINAL)))
		return 1;

	DEBUG(4, "Len: %d\n", msg->len);
	if(msg->len >= 7) {
		/* Get what we need */
		conn_hdr = (obex_connect_hdr_t *) ((msg->data) + 3);
		version = conn_hdr->version;
		flags   = conn_hdr->flags;
		mtu     = ntohs(conn_hdr->mtu);

		DEBUG(1, "version=%02x\n", version);

		/* Limit to some reasonable value (usually OBEX_DEFAULT_MTU) */
		if(mtu < self->mtu_tx_max)
			self->mtu_tx = mtu;
		else
			self->mtu_tx = self->mtu_tx_max;

		DEBUG(1, "requested MTU=%02x, used MTU=%02x\n", mtu, self->mtu_tx);
		return 1;
	}
	DEBUG(1, "Malformed connect-header received\n");
	return -1;
}
