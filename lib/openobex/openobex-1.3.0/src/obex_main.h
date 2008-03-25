/*********************************************************************
 *                
 * Filename:      obex_main.h
 * Version:       0.9
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Mon Jul 20 22:28:23 1998
 * CVS ID:        $Id: obex_main.h,v 1.20 2002/11/22 19:06:11 holtmann Exp $
 * 
 *     Copyright (c) 1999, 2000 Pontus Fuchs, All Rights Reserved.
 *     Copyright (c) 1998, 1999, 2000 Dag Brattli, All Rights Reserved.
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

#ifndef OBEX_MAIN_H
#define OBEX_MAIN_H

#include <time.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

/* Forward decl */
typedef struct obex obex_t;

#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif

#define	TRUE		1
#define FALSE		0

#define obex_return_if_fail(test)	do { if (!(test)) return; } while(0);
#define obex_return_val_if_fail(test, val)	do { if (!(test)) return val; } while(0);
		
#include "obex_const.h"
#include "obex_object.h"
#include "obex_transport.h"
#include "netbuf.h"

#ifdef OBEX_SYSLOG
#include <syslog.h>
#endif

/* use 0 for none, 1 for sendbuff, 2 for receivebuff and 3 for both */
#ifndef OBEX_DUMP
#define OBEX_DUMP 0
#endif

/* use 0 for production, 1 for verification, >2 for debug */
#ifndef OBEX_DEBUG
#define OBEX_DEBUG 0
#endif

#ifndef _WIN32

#  if OBEX_DEBUG
extern int obex_debug;
#    ifdef OBEX_SYSLOG
#    define DEBUG(n, format, args...) if (obex_debug >= (n)) syslog(LOG_DEBUG, "OpenOBEX: %s(): " format, __FUNCTION__ , ##args)
#    else
#    define DEBUG(n, format, args...) if (obex_debug >= (n)) fprintf(stderr, "%s(): " format, __FUNCTION__ , ##args)
#    endif	/* OBEX_SYSLOG */
#  else
#  define DEBUG(n, format, args...)
#  endif /* OBEX_DEBUG != 0 */

#  if OBEX_DUMP
extern int obex_dump;
#  define DUMPBUFFER(n, label, msg)	if (obex_dump & (n)) g_netbuf_print(label, msg);
#  else
#  define DUMPBUFFER(n, label, msg)
#  endif /* OBEX_DUMP != 0 */

#else /* _WIN32 */

void DEBUG(unsigned int n, ...);
void DUMPBUFFERS(n, label, msg);

#endif /* _WIN32 */

#define OBEX_VERSION		0x11      /* Version 1.1 */

// Note that this one is also defined in obex.h
typedef void (*obex_event_t)(obex_t *handle, obex_object_t *obj, int mode, int event, int obex_cmd, int obex_rsp);

#define MODE_SRV	0x80
#define MODE_CLI	0x00

enum
{
	STATE_IDLE,
	STATE_START,
	STATE_SEND,
	STATE_REC,
};

struct obex {
	uint16_t mtu_tx;			/* Maximum OBEX TX packet size */
        uint16_t mtu_rx;			/* Maximum OBEX RX packet size */
	uint16_t mtu_tx_max;		/* Maximum TX we can accept */

	int fd;			/* Socket descriptor */
	int serverfd;
	int writefd;		/* write descriptor - only OBEX_TRANS_FD */
        unsigned int state;
	
	int keepserver;		/* Keep server alive */
	int filterhint;		/* Filter devices based on hint bits */
	int filterias;		/* Filter devices based on IAS entry */

	GNetBuf *tx_msg;		/* Reusable transmit message */
	GNetBuf *rx_msg;		/* Reusable receive message */

	obex_object_t	*object;	/* Current object being transfered */      
	obex_event_t	eventcb;	/* Event-callback */

	obex_transport_t trans;		/* Transport being used */
	obex_ctrans_t ctrans;
	void * userdata;		/* For user */
};


int obex_create_socket(obex_t *self, int domain);
int obex_delete_socket(obex_t *self, int fd);

void obex_deliver_event(obex_t *self, int event, int cmd, int rsp, int del);
int obex_data_indication(obex_t *self, uint8_t *buf, int buflen);

void obex_response_request(obex_t *self, uint8_t opcode);
int obex_data_request(obex_t *self, GNetBuf *msg, int opcode);
int obex_cancelrequest(obex_t *self, int nice);

char *obex_response_to_string(int rsp);

#endif
