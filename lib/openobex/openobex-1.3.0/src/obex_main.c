/*********************************************************************
 *                
 * Filename:      obex_main.c
 * Version:       0.9
 * Description:   Implementation of the Object Exchange Protocol OBEX
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Fri Jul 17 23:02:02 1998
 * CVS ID:        $Id: obex_main.c,v 1.23 2002/11/22 19:06:11 holtmann Exp $
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

#ifdef _WIN32
#include <winsock.h>
#else /* _WIN32 */

#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>

#ifdef HAVE_BLUETOOTH
#include <bluetooth/bluetooth.h>
#endif /*HAVE_BLUETOOTH*/

#endif /* _WIN32 */

#include "obex_main.h"
#include "obex_header.h"
#include "obex_server.h"
#include "obex_client.h"
#include "obex_const.h"

#ifdef OBEX_DEBUG
int obex_debug;
#endif
#ifdef OBEX_DUMP
int obex_dump;
#endif

/*
 * Function obex_create_socket()
 *
 *    Create socket if needed.
 *
 */
int obex_create_socket(obex_t *self, int domain)
{
	int fd, proto;
	DEBUG(4, "\n");

	proto = 0;

#ifdef HAVE_BLUETOOTH
	if (domain == AF_BLUETOOTH)
		proto = BTPROTO_RFCOMM;
#endif /*HAVE_BLUETOOTH*/

	fd = socket(domain, SOCK_STREAM, proto);
	return fd;
}

/*
 * Function obex_delete_socket()
 *
 *    Close socket if opened.
 *
 */
int obex_delete_socket(obex_t *self, int fd)
{
	int ret;

	DEBUG(4, "\n");

	if(fd < 0)
		return fd;

#ifdef _WIN32
	ret = closesocket(fd);
#else /* _WIN32 */
	ret = close(fd);
#endif /* _WIN32 */
	return ret;
}


/*
 * Function obex_response_to_string(rsp)
 *
 *    Return a string of an OBEX-response
 *
 */
char *obex_response_to_string(int rsp)
{
	switch (rsp) {
	case OBEX_RSP_CONTINUE:
		return "Continue";
	case OBEX_RSP_SWITCH_PRO:
		return "Switching protocols";
	case OBEX_RSP_SUCCESS:
		return "OK, Success";
	case OBEX_RSP_CREATED:
		return "Created";
	case OBEX_RSP_ACCEPTED:
		return "Accepted";
	case OBEX_RSP_NO_CONTENT:
		return "No Content";
	case OBEX_RSP_BAD_REQUEST:
		return "Bad Request";
	case OBEX_RSP_UNAUTHORIZED:
		return "Unautorized";
	case OBEX_RSP_PAYMENT_REQUIRED:
		return "Payment required";
	case OBEX_RSP_FORBIDDEN:
		return "Forbidden";
	case OBEX_RSP_NOT_FOUND:
		return "Not found";
	case OBEX_RSP_METHOD_NOT_ALLOWED:
		return "Method not allowed";
	case OBEX_RSP_CONFLICT:
		return "Conflict";
	case OBEX_RSP_INTERNAL_SERVER_ERROR:
		return "Internal server error";
	case OBEX_RSP_NOT_IMPLEMENTED:
		return "Not implemented!";
	case OBEX_RSP_DATABASE_FULL:
		return "Database full";
	case OBEX_RSP_DATABASE_LOCKED:
		return "Database locked";
	default:
		return "Unknown response";
	}
}

/*
 * Function obex_deliver_event ()
 *
 *    Deliver an event to app.
 *
 */
void obex_deliver_event(obex_t *self, int event, int cmd, int rsp, int del)
{
	if(self->state & MODE_SRV)
		self->eventcb(self, self->object, OBEX_SERVER, event, cmd, rsp);
	else
		self->eventcb(self, self->object, OBEX_CLIENT, event, cmd, rsp);
	
	if(del == TRUE && self->object != NULL) {
		obex_object_delete(self->object);
		self->object = NULL;
	}
}

/*
 * Function obex_response_request (self, opcode)
 *
 *    Send a response to peer device
 *
 */
void obex_response_request(obex_t *self, uint8_t opcode)
{
	GNetBuf *msg;

	obex_return_if_fail(self != NULL);

	msg = g_netbuf_recycle(self->tx_msg);
	g_netbuf_reserve(msg, sizeof(obex_common_hdr_t));

	obex_data_request(self, msg, opcode | OBEX_FINAL);
}

/*
 * Function obex_data_request (self, opcode, cmd)
 *
 *    Send response or command code along with optional headers/data.
 *
 */
int obex_data_request(obex_t *self, GNetBuf *msg, int opcode)
{
	obex_common_hdr_t *hdr;
	int actual = 0;

	obex_return_val_if_fail(self != NULL, -1);
	obex_return_val_if_fail(msg != NULL, -1);

	/* Insert common header */
	hdr = (obex_common_hdr_t *) g_netbuf_push(msg, sizeof(obex_common_hdr_t));

	hdr->opcode = opcode;
	hdr->len = htons((uint16_t)msg->len);

	DUMPBUFFER(1, "Tx", msg);
	DEBUG(1, "len = %d bytes\n", msg->len);

	actual = obex_transport_write(self, msg);
	return actual;
}

/*
 * Function obex_data_indication (self)
 *
 *    Read/Feed some input from device and find out which packet it is
 *
 */
int obex_data_indication(obex_t *self, uint8_t *buf, int buflen)
{
	obex_common_hdr_t *hdr;
	GNetBuf *msg;
	int final;
	int actual = 0;
	unsigned int size;
	int ret;
	
	DEBUG(4, "\n");

	obex_return_val_if_fail(self != NULL, -1);

	msg = self->rx_msg;
	
	/* First we need 3 bytes to be able to know how much data to read */
	if(msg->len < 3)  {
		actual = obex_transport_read(self, 3 - (msg->len), buf, buflen);
		
		DEBUG(4, "Got %d bytes\n", actual);

		/* Check if we are still connected */
		if (actual <= 0)	{
			obex_deliver_event(self, OBEX_EV_LINKERR, 0, 0, TRUE);
			return actual;
		}
		buf += actual;
		buflen -= actual;
		g_netbuf_put(msg, actual);
	}

	/* If we have 3 bytes data we can decide how big the packet is */
	if(msg->len >= 3) {
		hdr = (obex_common_hdr_t *) msg->data;
		size = ntohs(hdr->len);

		actual = 0;
		if(msg->len != (int) ntohs(hdr->len)) {

			actual = obex_transport_read(self, size - msg->len, buf,
				buflen);

			/* Check if we are still connected */
			if (actual <= 0)	{
				obex_deliver_event(self, OBEX_EV_LINKERR, 0, 0, TRUE);
				return actual;
			}
		}
	}
        else {
		/* Wait until we have at least 3 bytes data */
		DEBUG(3, "Need at least 3 bytes got only %d!\n", msg->len);
		return actual;
        }


	/* New data has been inserted at the end of message */
	g_netbuf_put(msg, actual);
	DEBUG(1, "Got %d bytes msg len=%d\n", actual, msg->len);

	/*
	 * Make sure that the buffer we have, actually has the specified
	 * number of bytes. If not the frame may have been fragmented, and
	 * we will then need to read more from the socket.  
	 */

	/* Make sure we have a whole packet */
	if (size > msg->len) {
		DEBUG(3, "Need more data, size=%d, len=%d!\n",
		      size, msg->len);

		/* I'll be back! */
		return msg->len;
	}

	DUMPBUFFER(2, "Rx", msg);

	actual = msg->len;
	final = hdr->opcode & OBEX_FINAL; /* Extract final bit */

	/* Dispatch to the mode we are in */
	if(self->state & MODE_SRV) {
		ret = obex_server(self, msg, final);
		g_netbuf_recycle(msg);
		
	}
	else	{
		ret = obex_client(self, msg, final);
		g_netbuf_recycle(msg);
	}
	/* Check parse errors */
	if(ret < 0)
		actual = ret;
	return actual;
}

/*
 * Function obex_cancel_request ()
 *
 *    Cancel an ongoing request
 *
 */
int obex_cancelrequest(obex_t *self, int nice)
{
	/* If we have no ongoing request do nothing */
	if(self->object == NULL)
		return 0;

	/* Abort request without sending abort */
	if(!nice) {
		/* Deliver event will delete the object */
		obex_deliver_event(self, OBEX_EV_ABORT, 0, 0, TRUE);
		g_netbuf_recycle(self->tx_msg);
		g_netbuf_recycle(self->rx_msg);
		/* Since we didn't send ABORT to peer we are out of sync
		   and need to disconnect transport immediately, so we signal
		   link error to app */
		obex_deliver_event(self, OBEX_EV_LINKERR, 0, 0, FALSE);
		return 1;
	}
	
	/* Do a "nice" abort */
	DEBUG(4, "Nice abort not implemented yet!!\n");
	self->object->abort = TRUE;
	return 0;
}
