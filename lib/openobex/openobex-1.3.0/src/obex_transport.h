/*********************************************************************
 *                
 * Filename:      obex_transport.h
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Sat May  1 20:16:45 1999
 * CVS ID         $Id: obex_transport.h,v 1.9 2002/10/28 21:51:18 holtmann Exp $
 * 
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

#ifndef OBEX_TRANSPORT_H
#define OBEX_TRANSPORT_H

#ifdef _WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#endif

#ifdef HAVE_IRDA
#include "irda_wrap.h"
#endif /*HAVE_IRDA*/
#ifdef HAVE_BLUETOOTH
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#endif /*HAVE_BLUETOOTH*/

#include "obex_main.h"

typedef union {
#ifdef HAVE_IRDA
	struct sockaddr_irda irda;
#endif /*HAVE_IRDA*/
	struct sockaddr_in   inet;
#ifdef HAVE_BLUETOOTH
	struct sockaddr_rc   rfcomm;
#endif /*HAVE_BLUETOOTH*/
} saddr_t;

typedef struct obex_transport {
	int	type;
     	int connected;	/* Link connection state */
     	unsigned int	mtu;		/* Tx MTU of the link */
	saddr_t	self;		/* Source address */
	saddr_t	peer;		/* Destination address */

} obex_transport_t;

int obex_transport_accept(obex_t *self);

int obex_transport_handle_input(obex_t *self, int timeout);
int obex_transport_connect_request(obex_t *self);
void obex_transport_disconnect_request(obex_t *self);
int obex_transport_listen(obex_t *self);
void obex_transport_disconnect_server(obex_t *self);
int obex_transport_write(obex_t *self, GNetBuf *msg);
int obex_transport_read(obex_t *self, int count, uint8_t *buf, int buflen);


#endif OBEX_TRANSPORT_H



