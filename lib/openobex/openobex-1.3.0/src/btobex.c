/*************************************<********************************
 *                
 * Filename:      btobex.c
 * Version:       0.1
 * Description:   Bluetooth OBEX, Bluetooth transport for OBEX
 * Status:        Experimental.
 * Author:        Marcel Holtmann <marcel@holtmann.org>
 * Created at:    Fri Aug 23 14:28:13 2002
 * CVS ID:        $Id: btobex.c,v 1.5 2002/11/22 19:06:08 holtmann Exp $
 * 
 *     Copyright (c) 2002 Marcel Holtmann, All Rights Reserved.
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

#ifdef HAVE_BLUETOOTH

#ifdef _WIN32
#include <winsock.h>

#else /* _WIN32 */
/* Linux case */

#include <string.h>
#include <unistd.h>
#include <stdio.h>		/* perror */
#include <errno.h>		/* errno and EADDRNOTAVAIL */
#include <netinet/in.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#endif /* _WIN32 */


#include <obex_main.h>
#include <btobex.h>


/*
 * Function btobex_prepare_connect (self, service)
 *
 *    Prepare for Bluetooth RFCOMM connect
 *
 */
void btobex_prepare_connect(obex_t *self, bdaddr_t *src, bdaddr_t *dst, uint8_t channel)
{
#ifndef _WIN32
	self->trans.self.rfcomm.rc_family = AF_BLUETOOTH;
	bacpy(&self->trans.self.rfcomm.rc_bdaddr, src);
	self->trans.self.rfcomm.rc_channel = 0;

	self->trans.peer.rfcomm.rc_family = AF_BLUETOOTH;
	bacpy(&self->trans.peer.rfcomm.rc_bdaddr, dst);
	self->trans.peer.rfcomm.rc_channel = htobs(channel);
#endif /* _WIN32 */
}

/*
 * Function btobex_prepare_listen (self, service)
 *
 *    Prepare for Bluetooth RFCOMM listen
 *
 */
void btobex_prepare_listen(obex_t *self, bdaddr_t *src, uint8_t channel)
{
#ifndef _WIN32
	/* Bind local service */
	self->trans.self.rfcomm.rc_family = AF_BLUETOOTH;
	bacpy(&self->trans.self.rfcomm.rc_bdaddr, src);
	self->trans.self.rfcomm.rc_channel = htobs(channel);
#endif /* _WIN32 */
}

/*
 * Function btobex_listen (self)
 *
 *    Listen for incoming connections.
 *
 */
int btobex_listen(obex_t *self)
{
#ifndef _WIN32
	DEBUG(3, "\n");

	self->serverfd = obex_create_socket(self, AF_BLUETOOTH);
	if(self->serverfd < 0) {
		DEBUG(0, "Error creating socket\n");
		return -1;
	}
	
	if (bind(self->serverfd, (struct sockaddr*) &self->trans.self.rfcomm, 
		 sizeof(struct sockaddr_rc)))
	{
		DEBUG(0, "Error doing bind\n");
		goto out_freesock;
	}


	if (listen(self->serverfd, 1)) {
		DEBUG(0, "Error doing listen\n");
		goto out_freesock;
	}

	DEBUG(4, "We are now listening for connections\n");
	return 1;

out_freesock:
	obex_delete_socket(self, self->serverfd);
	self->serverfd = -1;
#endif /* _WIN32 */
	return -1;
}

/*
 * Function btobex_accept (self)
 *
 *    Accept an incoming connection.
 *
 * Note : don't close the server socket here, so apps may want to continue
 * using it...
 */
int btobex_accept(obex_t *self)
{
#ifndef _WIN32
	int addrlen = sizeof(struct sockaddr_rc);
	//int mtu;
	//int len = sizeof(int);

	// First accept the connection and get the new client socket.
	self->fd = accept(self->serverfd, (struct sockaddr *) &self->trans.peer.rfcomm,
 			  &addrlen);

	if (self->fd < 0) {
		return -1;
	}

	self->trans.mtu = OBEX_DEFAULT_MTU;
#endif /* _WIN32 */
	return 0;
}
	
/*
 * Function btobex_irda_connect_request (self)
 *
 *    Open the RFCOMM connection
 *
 */
int btobex_connect_request(obex_t *self)
{
	int ret;
#ifndef _WIN32
	int mtu = 0;
	//int len = sizeof(int);

	DEBUG(4, "\n");

	if(self->fd < 0)	{
		self->fd = obex_create_socket(self, AF_BLUETOOTH);
		if(self->fd < 0)
			return -1;
	}

	ret = bind(self->fd, (struct sockaddr*) &self->trans.self.rfcomm,
		   sizeof(struct sockaddr_rc));

	if (ret < 0) {
		DEBUG(4, "ret=%d\n", ret);
		goto out_freesock;
	}

	ret = connect(self->fd, (struct sockaddr*) &self->trans.peer.rfcomm,
		      sizeof(struct sockaddr_rc));
	if (ret < 0) {
		DEBUG(4, "ret=%d\n", ret);
		goto out_freesock;
	}

	mtu = OBEX_DEFAULT_MTU;
	self->trans.mtu = mtu;

	DEBUG(2, "transport mtu=%d\n", mtu);

	return 1;

out_freesock:
	obex_delete_socket(self, self->fd);
	self->fd = -1;
#endif /* _WIN32 */
	return ret;	
}

/*
 * Function btobex_link_disconnect_request (self)
 *
 *    Shutdown the RFCOMM link
 *
 */
int btobex_disconnect_request(obex_t *self)
{
	int ret;
#ifndef _WIN32
	DEBUG(4, "\n");
	ret = obex_delete_socket(self, self->fd);
	if(ret < 0)
		return ret;
	self->fd = -1;
#endif /* _WIN32 */
	return ret;	
}

/*
 * Function btobex_link_disconnect_server (self)
 *
 *    Close the server socket
 *
 * Used when we start handling a incomming request, or when the
 * client just want to quit...
 */
int btobex_disconnect_server(obex_t *self)
{
	int ret;
#ifndef _WIN32
	DEBUG(4, "\n");
	ret = obex_delete_socket(self, self->serverfd);
	self->serverfd = -1;
#endif /* _WIN32 */
	return ret;	
}

#endif /* HAVE_BLUETOOTH */
