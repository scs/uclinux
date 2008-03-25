/*************************************<********************************
 *                
 * Filename:      irobex.c
 * Version:       0.6
 * Description:   IrOBEX, IrDA transport for OBEX
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Fri Apr 23 14:28:13 1999
 * CVS ID:        $Id: irobex.c,v 1.16 2002/11/22 19:06:09 holtmann Exp $
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *     Copyright (c) 2000 Pontus Fuchs, All Rights Reserved.
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

#ifdef HAVE_IRDA

#ifdef _WIN32
#include <winsock.h>

#include <irda_wrap.h>

#else /* _WIN32 */
/* Linux case */

#include <string.h>
#include <unistd.h>
#include <stdio.h>		/* perror */
#include <errno.h>		/* errno and EADDRNOTAVAIL */
#include <netinet/in.h>
#include <sys/socket.h>

#include "irda_wrap.h"

#ifndef AF_IRDA
#define AF_IRDA 23
#endif /* AF_IRDA */
#endif /* _WIN32 */


#include <obex_main.h>
#include <irobex.h>


/*
 * Function irobex_no_addr (addr)
 *
 *    Check if the address is not valid for connection
 *
 */
static inline int irobex_no_addr(struct sockaddr_irda *addr)
{
#ifndef _WIN32
	return((addr->sir_addr == 0x0) || (addr->sir_addr == 0xFFFFFFFF));
#else
	return( ((addr->irdaDeviceID[0] == 0x00) &&
		 (addr->irdaDeviceID[1] == 0x00) &&
		 (addr->irdaDeviceID[2] == 0x00) &&
		 (addr->irdaDeviceID[3] == 0x00)) ||
		((addr->irdaDeviceID[0] == 0xFF) &&
		 (addr->irdaDeviceID[1] == 0xFF) &&
		 (addr->irdaDeviceID[2] == 0xFF) &&
		 (addr->irdaDeviceID[3] == 0xFF)) );
#endif /* _WIN32 */
}

/*
 * Function irobex_prepare_connect (self, service)
 *
 *    Prepare for IR-connect
 *
 */
void irobex_prepare_connect(obex_t *self, const char *service)
{
	self->trans.peer.irda.sir_family = AF_IRDA;

	if (service)
		strncpy(self->trans.peer.irda.sir_name, service, 25);
	else
		strcpy(self->trans.peer.irda.sir_name, "OBEX");
}

/*
 * Function irobex_prepare_listen (self, service)
 *
 *    Prepare for IR-listen
 *
 */
void irobex_prepare_listen(obex_t *self, const char *service)
{
	/* Bind local service */
	self->trans.self.irda.sir_family = AF_IRDA;

	if (service == NULL)
		strncpy(self->trans.self.irda.sir_name, "OBEX", 25);
	else
		strncpy(self->trans.self.irda.sir_name, service, 25);


#ifndef _WIN32
	self->trans.self.irda.sir_lsap_sel = LSAP_ANY;
#endif /* _WIN32 */
}

/*
 * Function irobex_listen (self)
 *
 *    Listen for incoming connections.
 *
 */
int irobex_listen(obex_t *self)
{
	DEBUG(3, "\n");

	self->serverfd = obex_create_socket(self, AF_IRDA);
	if(self->serverfd < 0) {
		DEBUG(0, "Error creating socket\n");
		return -1;
	}
	
	if (bind(self->serverfd, (struct sockaddr*) &self->trans.self.irda, 
		 sizeof(struct sockaddr_irda)))
	{
		DEBUG(0, "Error doing bind\n");
		goto out_freesock;
	}

#ifndef _WIN32
	/* Ask the IrDA stack to advertise the Obex hint bit - Jean II */
	/* Under Linux, it's a regular socket option */
	{
		unsigned char	hints[4];	/* Hint be we advertise */

		/* We want to advertise the OBEX hint bit */
		hints[0] = HINT_EXTENSION;
		hints[1] = HINT_OBEX;

		/* Tell the stack about it */
		if (setsockopt(self->serverfd, SOL_IRLMP, IRLMP_HINTS_SET,
			       hints, sizeof(hints))) {
			/* This command is not supported by older kernels,
			   so ignore any errors! */
		}
	}
#else /* _WIN32 */
	/* Ask the IrDA stack to advertise the Obex hint bit */
	/* Under Windows, it's a complicated story */
#endif /* _WIN32 */

	if (listen(self->serverfd, 1)) {
		DEBUG(0, "Error doing listen\n");
		goto out_freesock;
	}

	DEBUG(4, "We are now listening for connections\n");
	return 1;

out_freesock:
	obex_delete_socket(self, self->serverfd);
	self->serverfd = -1;
	return -1;
}

/*
 * Function irobex_accept (self)
 *
 *    Accept an incoming connection.
 *
 * Note : don't close the server socket here, so apps may want to continue
 * using it...
 */
int irobex_accept(obex_t *self)
{
	int addrlen = sizeof(struct sockaddr_irda);
	int mtu;
	int len = sizeof(int);

	// First accept the connection and get the new client socket.
	self->fd = accept(self->serverfd, (struct sockaddr *) &self->trans.peer.irda,
 			  &addrlen);

	if (self->fd < 0) {
		return -1;
	}

#ifndef _WIN32
	/* Check what the IrLAP data size is */
	if (getsockopt(self->fd, SOL_IRLMP, IRTTP_MAX_SDU_SIZE, (void *) &mtu, 
		       &len)) 
	{
		return -1;
	}
	self->trans.mtu = mtu;
	DEBUG(3, "transport mtu=%d\n", mtu);
#else
	self->trans.mtu = OBEX_DEFAULT_MTU;
#endif /* _WIN32 */
	return 0;
}
	
/* Memory allocation for discovery */
#define DISC_BUF_LEN	sizeof(struct irda_device_list) + \
			sizeof(struct irda_device_info) * (MAX_DEVICES)
/*
 * Function irobex_discover_devices (self)
 *
 *    Try to discover some remote device(s) that we can connect to
 *
 * Note : we optionally can do a first filtering on the Obex hint bit,
 * and then we can verify that the device does have the requested service...
 * Note : in this function, the memory allocation for the discovery log
 * is done "the right way", so that it's safe and we don't leak memory...
 * Jean II
 */
static int irobex_discover_devices(obex_t *self)
{
	struct irda_device_list *	list;
	unsigned char		buf[DISC_BUF_LEN];
	int ret = -1;
	int err;
	int len;
	int i;

#ifndef _WIN32
	/* Hint bit filtering. Linux case */
	if(self->filterhint) {
		unsigned char	hints[4];	/* Hint be we filter on */

		/* We want only devices that advertise OBEX hint */
		hints[0] = HINT_EXTENSION;
		hints[1] = HINT_OBEX;

		/* Set the filter used for performing discovery */
		if (setsockopt(self->fd, SOL_IRLMP, IRLMP_HINT_MASK_SET,
			       hints, sizeof(hints))) {
			perror("setsockopt:");
			return(-1);
		}
	}
#endif /* _WIN32 */

	/* Set the list to point to the correct place */
	list = (struct irda_device_list *) buf;
	len = DISC_BUF_LEN;

	/* Perform a discovery and get device list */
	if (getsockopt(self->fd, SOL_IRLMP, IRLMP_ENUMDEVICES, buf, &len)) {
		DEBUG(1, "Didn't find any devices!\n");
		return(-1);
	}

#ifndef _WIN32
	/* Did we get any ? (in some rare cases, this test is true) */
	if (list->len <= 0) {
		DEBUG(1, "Didn't find any devices!\n");
		return(-1);
	}

	/* List all Obex devices : Linux case */
	DEBUG(1, "Discovered %d devices :\n", list->len);
	for(i = 0; i < list->len; i++) {
		DEBUG(1, "  [%d] name:  %s, daddr: 0x%08x",
		      i + 1, list->dev[i].info, list->dev[i].daddr);
		//fflush(stdout);

		/* Do we want to filter devices based on IAS ? */
		if(self->filterias) {
			struct irda_ias_set ias_query;
			/* Ask if the requested service exist on this device */
			len = sizeof(ias_query);
			ias_query.daddr = list->dev[i].daddr;
			strcpy(ias_query.irda_class_name,
			       self->trans.peer.irda.sir_name);
			strcpy(ias_query.irda_attrib_name,
			       "IrDA:TinyTP:LsapSel");
			err = getsockopt(self->fd, SOL_IRLMP, IRLMP_IAS_QUERY,
					 &ias_query, &len);
			/* Check if we failed */
			if(err != 0) {
				if(errno != EADDRNOTAVAIL) {
					DEBUG(1, " <can't query IAS>\n");
				} else {
					DEBUG(1, ", doesn't have %s\n",
					      self->trans.peer.irda.sir_name);
				}
				/* Go back to for(;;) */
				continue;
			}
			DEBUG(1, ", has service %s\n",
			      self->trans.peer.irda.sir_name);
		}
		else {
			DEBUG(1, "\n");
		}

		/* Pick this device */
		self->trans.peer.irda.sir_addr = list->dev[i].daddr;
		self->trans.self.irda.sir_addr = list->dev[i].saddr;
		ret = 0;
	}
#else
	/* List all Obex devices : Win32 case */
	if (len > 0) {
		DEBUG(1, "Discovered: (list len=%d)\n", list->numDevice);

		for (i=0; i<(int)list->numDevice; i++) {
			DEBUG(1, "  name:  %s\n", list->Device[i].irdaDeviceName);
			DEBUG(1, "  daddr: %08x\n", list->Device[i].irdaDeviceID);
			memcpy(&self->trans.peer.irda.irdaDeviceID[0], &list->Device[i].irdaDeviceID[0], 4);
			ret = 0;
		}
	}
#endif /* _WIN32 */

	if(ret <  0)
		DEBUG(1, "didn't find any OBEX devices!\n");
	return(ret);
}

/*
 * Function irobex_irda_connect_request (self)
 *
 *    Open the TTP connection
 *
 */
int irobex_connect_request(obex_t *self)
{
	int mtu = 0;
	int len = sizeof(int);
	int ret;

	DEBUG(4, "\n");

	if(self->fd < 0)	{
		self->fd = obex_create_socket(self, AF_IRDA);
		if(self->fd < 0)
			return -1;
	}

	/* Check if the application did supply a valid address.
	 * You need to use OBEX_TransportConnect() for that. Jean II */
	if(irobex_no_addr(&self->trans.peer.irda)) {
		/* Nope. Go find one... */
		ret = irobex_discover_devices(self);
		if (ret < 0)	{
			DEBUG(1, "No devices in range\n");
			goto out_freesock;
		}
	}

	ret = connect(self->fd, (struct sockaddr*) &self->trans.peer.irda,
		      sizeof(struct sockaddr_irda));
	if (ret < 0) {
		DEBUG(4, "ret=%d\n", ret);
		goto out_freesock;
	}

#ifndef _WIN32
	/* Check what the IrLAP data size is */
	ret = getsockopt(self->fd, SOL_IRLMP, IRTTP_MAX_SDU_SIZE, 
			 (void *) &mtu, &len);
	if (ret < 0) {
		goto out_freesock;
	}
#else
	mtu = 512;
#endif
	self->trans.mtu = mtu;

	DEBUG(2, "transport mtu=%d\n", mtu);
	
	return 1;

out_freesock:
	obex_delete_socket(self, self->fd);
	self->fd = -1;
	return ret;	
}

/*
 * Function irobex_link_disconnect_request (self)
 *
 *    Shutdown the IrTTP link
 *
 */
int irobex_disconnect_request(obex_t *self)
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
 * Function irobex_link_disconnect_server (self)
 *
 *    Close the server socket
 *
 * Used when we start handling a incomming request, or when the
 * client just want to quit...
 */
int irobex_disconnect_server(obex_t *self)
{
	int ret;
	DEBUG(4, "\n");
	ret = obex_delete_socket(self, self->serverfd);
	self->serverfd = -1;
	return ret;	
}

#endif /* HAVE_IRDA */
