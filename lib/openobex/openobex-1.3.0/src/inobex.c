/*********************************************************************
 *                
 * Filename:      inobex.c
 * Version:       
 * Description:   InOBEX, Inet transport for OBEX.
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Sat Apr 17 16:50:35 1999
 * CVS ID:	  $Id: inobex.c,v 1.12 2002/11/22 19:06:08 holtmann Exp $
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#ifdef _WIN32
#include <winsock.h>
#else

#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/socket.h>
#endif /*_WIN32*/
#include "obex_main.h"

#define OBEX_PORT 650

/*
 * Function inobex_prepare_connect (self, service)
 *
 *    Prepare for INET-connect
 *
 */
void inobex_prepare_connect(obex_t *self, struct sockaddr *saddr, int addrlen)
{
	memcpy(&self->trans.peer, saddr, addrlen);
	/* Override to be safe... */
	self->trans.peer.inet.sin_family = AF_INET;
	self->trans.peer.inet.sin_port = htons(OBEX_PORT);
}

/*
 * Function inobex_prepare_listen (self)
 *
 *    Prepare for INET-listen
 *
 */
void inobex_prepare_listen(obex_t *self)
{
	/* Bind local service */
	self->trans.self.inet.sin_family = AF_INET;
	self->trans.self.inet.sin_port = htons(OBEX_PORT);
	self->trans.self.inet.sin_addr.s_addr = INADDR_ANY;
}

/*
 * Function inobex_listen (self)
 *
 *    Wait for incomming connections
 *
 */
int inobex_listen(obex_t *self)
{
	DEBUG(4, "\n");

	self->serverfd = obex_create_socket(self, AF_INET);
	if(self->serverfd < 0) {
		DEBUG(0, "Cannot create server-socket\n");
		return -1;
	}

	//printf("TCP/IP listen %d %X\n", self->trans.self.inet.sin_port,
	//       self->trans.self.inet.sin_addr.s_addr);
	if (bind(self->serverfd, (struct sockaddr*) &self->trans.self.inet,
		 sizeof(struct sockaddr_in))) 
	{
		DEBUG(0, "bind() Failed\n");
		return -1;
	}

	if (listen(self->serverfd, 2)) {
		DEBUG(0, "listen() Failed\n");
		return -1;
	}

	DEBUG(4, "Now listening for incomming connections. serverfd = %d\n", self->serverfd);
	return 1;
}

/*
 * Function inobex_accept (self)
 *
 *    Accept incoming connection.
 *
 * Note : don't close the server socket here, so apps may want to continue
 * using it...
 */
int inobex_accept(obex_t *self)
{
	int addrlen = sizeof(struct sockaddr_in);

	self->fd = accept(self->serverfd, (struct sockaddr *) 
		&self->trans.peer.inet, &addrlen);

	if(self->fd < 0)
		return -1;

	/* Just use the default MTU for now */
	self->trans.mtu = OBEX_DEFAULT_MTU;
	return 1;
}
	

/*
 * Function inobex_connect_request (self)
 *
 *    
 *
 */
int inobex_connect_request(obex_t *self)
{
	unsigned char *addr;
	int ret;

	self->fd = obex_create_socket(self, AF_INET);
	if(self->fd < 0)
		return -1;

	/* Set these just in case */
	self->trans.peer.inet.sin_family = AF_INET;
	self->trans.peer.inet.sin_port = htons(OBEX_PORT);

	addr = (char *) &self->trans.peer.inet.sin_addr.s_addr;

	DEBUG(2, "peer addr = %d.%d.%d.%d\n",
		addr[0], addr[1], addr[2], addr[3]);


	ret = connect(self->fd, (struct sockaddr*) &self->trans.peer.inet, 
		      sizeof(struct sockaddr_in));
	if (ret < 0) {
		DEBUG(4, "Connect failed\n");
		obex_delete_socket(self, self->fd);
		self->fd = -1;
		return ret;
	}

	self->trans.mtu = OBEX_DEFAULT_MTU;
	DEBUG(3, "transport mtu=%d\n", self->trans.mtu);

	return ret;
}

/*
 * Function inobex_transport_disconnect_request (self)
 *
 *    Shutdown the TCP/IP link
 *
 */
int inobex_disconnect_request(obex_t *self)
{
	int ret;
	DEBUG(4, "\n");
	ret = obex_delete_socket(self, self->fd);
	if(ret < 0)
		return ret;
	self->fd = -1;
	return ret;	
}

/*
 * Function inobex_transport_disconnect_server (self)
 *
 *    Close the server socket
 *
 * Used when we start handling a incomming request, or when the
 * client just want to quit...
 */
int inobex_disconnect_server(obex_t *self)
{
	int ret;
	DEBUG(4, "\n");
	ret = obex_delete_socket(self, self->serverfd);
	self->serverfd = -1;
	return ret;	
}
