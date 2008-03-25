/*********************************************************************
 *                
 * Filename:      obex_client.c
 * Version:       0.8
 * Description:   Handles client operations
 * Status:        Experimental.
 * Author:        Pontus Fuchs <pontus.fuchs@tactel.se>
 * Created at:    Thu Nov 11 20:56:00 1999
 * CVS ID:        $Id: obex_client.c,v 1.14 2002/11/22 19:06:10 holtmann Exp $
 *
 *     Copyright (c) 1999-2000 Pontus Fuchs, All Rights Reserved.
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

#include <stdlib.h>
#include <stdio.h>

#include "obex_main.h"
#include "obex_header.h"
#include "obex_connect.h"

/*
 * Function obex_client ()
 *
 *    Handle client operations
 *
 */
int obex_client(obex_t *self, GNetBuf *msg, int final)
{
	obex_common_hdr_t *response = NULL;
	int rsp = OBEX_RSP_BAD_REQUEST, ret;
	
	DEBUG(4, "\n");

	/* If this is a response we have some data in msg */
	if(msg) {
		response = (obex_common_hdr_t *) msg->data;
		rsp = response->opcode & ~OBEX_FINAL;
	}
	
	switch(self->state)
	{
	case STATE_SEND:
		/* In progress of sending request */
		DEBUG(4, "STATE_SEND\n");
		
		/* Any errors from peer? Win2k will send RSP_SUCCESS after
		   every fragment sent so we have to accept that too.*/
		if(rsp != OBEX_RSP_SUCCESS && rsp != OBEX_RSP_CONTINUE) {
			DEBUG(0, "STATE_SEND. request not accepted.\n");
			obex_deliver_event(self, OBEX_EV_REQDONE, self->object->opcode, rsp, TRUE);
			/* This is not an Obex error, it is just that the peer
			 * doesn't accept the request, so return 0 - Jean II */
			return 0;
		}
				
		if(ntohs(response->len) > 3) {
			DEBUG(1, "STATE_SEND. Didn't excpect data from peer (%d)\n", ntohs(response->len));
			DUMPBUFFER(4, "unexpected data", msg);
			/* At this point, we are in the middle of sending
			 * our request to the server, and it is already
			 * sending us some data ! This break the whole
			 * Request/Response model of HTTP !
			 * Most often, the server is sending some out of band
			 * progress information for a PUT.
			 * This is the way we will handle that :
			 * Save this header in our Rx header list. We can have
			 * duplicated header, so no problem...
			 * User can check the header in the next EV_PROGRESS,
			 * doing so will hide the header (until reparse).
			 * If not, header will be parsed at 'final', or just
			 * ignored (common case for PUT).
			 * Don't send any additional event to the app to not
			 * break compatibility and because app can just check
			 * this condition itself...
			 * No headeroffset needed because 'connect' is
			 * single packet (or we deny it).
			 * Jean II */
			if((self->object->opcode == OBEX_CMD_CONNECT) ||
			   (obex_object_receive(self, msg) < 0))	{
				obex_deliver_event(self, OBEX_EV_PARSEERR, self->object->opcode, 0, TRUE);
				self->state = MODE_SRV | STATE_IDLE;
				return -1;
			}
			obex_deliver_event(self, OBEX_EV_UNEXPECTED, self->object->opcode, 0, FALSE);
			/* Note : we may want to get rid of received header,
			 * however they are mixed with legitimate headers,
			 * and the user may expect to consult them later.
			 * So, leave them here (== overhead). Jean II */
		}
		// No break here!! Fallthrough	
	
	case STATE_START:
		/* Nothing has been sent yet */
		DEBUG(4, "STATE_START\n");
		
		ret = obex_object_send(self, self->object, TRUE, FALSE);
		if(ret < 0) {
			/* Error while sending */
			obex_deliver_event(self, OBEX_EV_LINKERR, self->object->opcode, 0, TRUE);
			self->state = MODE_CLI | STATE_IDLE;
		}
		else if (ret == 0) {
			/* Some progress made */			
			obex_deliver_event(self, OBEX_EV_PROGRESS, self->object->opcode, 0, FALSE);
                	self->state = MODE_CLI | STATE_SEND;
		}
                else {
                	/* Sending of object finished.. */
                	self->state = MODE_CLI | STATE_REC;
			// Should we deliver a EV_PROGRESS here ? Jean II
                }
		break;
			
	case STATE_REC:
		/* Receiving answer of request */
		DEBUG(4, "STATE_REC\n");
		
		/* Response of a CMD_CONNECT needs some special treatment.*/
		if(self->object->opcode == OBEX_CMD_CONNECT)	{
			DEBUG(2, "We expect a connect-rsp\n");
			if(obex_parse_connect_header(self, msg) < 0)	{
				obex_deliver_event(self, OBEX_EV_PARSEERR, self->object->opcode, 0, TRUE);
				self->state = MODE_SRV | STATE_IDLE;
				return -1;
			}
			self->object->headeroffset=4;
		}

		/* So does CMD_DISCONNECT */
		if(self->object->opcode == OBEX_CMD_DISCONNECT)	{
			DEBUG(2, "CMD_DISCONNECT done. Resetting MTU!\n");
			self->mtu_tx = OBEX_MINIMUM_MTU;
		}

		/* Receive any headers */
		if(obex_object_receive(self, msg) < 0)	{
			obex_deliver_event(self, OBEX_EV_PARSEERR, self->object->opcode, 0, TRUE);
			self->state = MODE_SRV | STATE_IDLE;
			return -1;
		}
	
		/* Are we done yet? */
		if(rsp == OBEX_RSP_CONTINUE) {
			DEBUG(3, "Continue...\n");
			if(obex_object_send(self, self->object, TRUE, FALSE) < 0)
				obex_deliver_event(self, OBEX_EV_LINKERR, self->object->opcode, 0, TRUE);
			else
				obex_deliver_event(self, OBEX_EV_PROGRESS, self->object->opcode, 0, FALSE);
		}
		else	{
			/* Notify app that client-operation is done! */
			DEBUG(3, "Done! Rsp=%02x!\n", rsp);
			obex_deliver_event(self, OBEX_EV_REQDONE, self->object->opcode, rsp, TRUE);
			self->state = MODE_SRV | STATE_IDLE;
		}
		break;
       	
       	default:
		DEBUG(0, "Unknown state\n");		
		obex_deliver_event(self, OBEX_EV_PARSEERR, rsp, 0, TRUE);
		return -1;
	}

	return 0;
}
