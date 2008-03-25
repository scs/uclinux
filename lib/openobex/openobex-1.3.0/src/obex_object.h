/*********************************************************************
 *                
 * Filename:      obex_object.h
 * Version:       0.9
 * Description:   
 * Status:        Stable.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Fri Apr 23 14:05:28 1999
 * CVS ID:        $Id: obex_object.h,v 1.11 2002/10/28 21:51:18 holtmann Exp $
 * 
 *     Copyright (c) 1999, 2000 Dag Brattli, All Rights Reserved.
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

#ifndef OBEX_OBJECT_H
#define OBEX_OBJECT_H

#include "obex_main.h"
#include "netbuf.h"

/* If an object has no expected length we have to 
reallocated every OBEX_OBJECT_ALLOCATIONTRESHOLD bytes */
#define OBEX_OBJECT_ALLOCATIONTRESHOLD 10240

struct obex_header_element {
	GNetBuf *buf;
	uint8_t hi;
	unsigned int length;
	unsigned int offset;
	int body_touched;
	int stream;
};

typedef struct {
        time_t time;

	slist_t *tx_headerq;		/* List of headers to transmit*/
	slist_t *rx_headerq;		/* List of received headers */
	slist_t *rx_headerq_rm;		/* List of recieved header already read by the app */
	GNetBuf *rx_body;		/* The rx body header need some extra help */
	GNetBuf *tx_nonhdr_data;	/* Data before of headers (like CONNECT and SETPATH) */
	GNetBuf *rx_nonhdr_data;	/* -||- */

	uint8_t cmd;			/* The command of this object */
					
					/* The opcode fields are used as
					   command when sending and response
					   when recieving */

	uint8_t opcode;			/* Opcode for normal packets */
	uint8_t lastopcode;		/* Opcode for last packet */
	unsigned int headeroffset;		/* Where to start parsing headers */

	int hinted_body_len;		/* Hinted body-length or 0 */
	int totallen;			/* Size of all headers */
        int abort;			/* Request shall be aborted */
	
	const uint8_t *s_buf;		/* Pointer to streaming data */
	unsigned int s_len;			/* Length of stream-data */
        unsigned int s_offset;			/* Current offset in buf */
        int s_stop;		/* End of stream */
        int s_srv;			/* Deliver body as stream when server */

} obex_object_t;


obex_object_t *obex_object_new(void);
int obex_object_delete(obex_object_t *object);
int obex_object_addheader(obex_t *self, obex_object_t *object, uint8_t hi,
				obex_headerdata_t hv, uint32_t hv_size,
				unsigned int flags);
int obex_object_getnextheader(obex_t *self, obex_object_t *object, uint8_t *hi,
				obex_headerdata_t *hv, uint32_t *hv_size);
int obex_object_reparseheaders(obex_t *self, obex_object_t *object);
int obex_object_setcmd(obex_object_t *object, uint8_t cmd, uint8_t lastcmd);
int obex_object_setrsp(obex_object_t *object, uint8_t rsp, uint8_t lastrsp);
int obex_object_send(obex_t *self, obex_object_t *object,
		      int allowfinalcmd, int forcefinalbit);
int obex_object_receive(obex_t *self, GNetBuf *msg);
int obex_object_readstream(obex_t *self, obex_object_t *object, const uint8_t **buf);

#endif
