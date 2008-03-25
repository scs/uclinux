/*********************************************************************
 *                
 * Filename:      obex_const.h
 * Version:       
 * Description:   Lots of constants and some typedefs for OpenOBEX.
 * Status:        Stable.
 * Author:        Pontus Fuchs <pontus.fuchs@tactel.se>
 * Created at:    Mon May 08 15:03:03 2000
 * CVS ID:        $Id: obex_const.h,v 1.20 2002/11/15 09:08:54 holtmann Exp $
 * 
 *     Copyright (c) 2000, Pontus Fuchs, All Rights Reserved.
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

#ifndef OBEX_CONST_H
#define OBEX_CONST_H

#include <stdint.h>

typedef union {
	uint32_t bq4;
	uint8_t bq1;
	const uint8_t *bs;
} obex_headerdata_t;

typedef struct {
	int (*connect)(obex_t *handle, void * customdata);
	int (*disconnect)(obex_t *handle, void * customdata);
	int (*listen)(obex_t *handle, void * customdata);
	int (*write)(obex_t *handle, void * customdata, uint8_t *buf, int buflen);
	int (*handleinput)(obex_t *handle, void * customdata, int timeout);
	void * customdata;
} obex_ctrans_t;

#define	OBEX_CLIENT		0
#define	OBEX_SERVER		1

/* Possible events */
#define OBEX_EV_PROGRESS	0	/* Progress has been made */
#define OBEX_EV_REQHINT		1	/* An incoming request is about to come */
#define OBEX_EV_REQ		2	/* An incoming request has arrived */
#define OBEX_EV_REQDONE		3	/* Request has finished */
#define OBEX_EV_LINKERR		4	/* Link has been disconnected */
#define OBEX_EV_PARSEERR	5	/* Malformed data encountered */
#define OBEX_EV_ACCEPTHINT	6	/* Connection accepted */
#define OBEX_EV_ABORT		7	/* Request was aborted */
#define OBEX_EV_STREAMEMPTY	8	/* Need to feed more data when sending a stream */
#define OBEX_EV_STREAMAVAIL	9	/* Time to pick up data when receiving a stream */
#define OBEX_EV_UNEXPECTED	10	/* Unexpected data, not fatal */

/* For OBEX_Init() */
#define OBEX_FL_KEEPSERVER	0x02	/* Keep the server alive */
#define OBEX_FL_FILTERHINT	0x04	/* Filter devices based on hint bit */
#define OBEX_FL_FILTERIAS	0x08	/* Filter devices based on IAS entry */

/* For OBEX_ObjectAddHeader */
#define OBEX_FL_FIT_ONE_PACKET	0x01	/* This header must fit in one packet */
#define OBEX_FL_STREAM_START	0x02	/* Start of streaming body */
#define OBEX_FL_STREAM_DATA	0x04	/* Body-stream data */
#define OBEX_FL_STREAM_DATAEND	0x08	/* Body stream last data */

/* Transports */
#define OBEX_TRANS_IRDA		1
#define OBEX_TRANS_INET		2
#define OBEX_TRANS_CUST		3	/* Fixme: This will go away in future */
#define OBEX_TRANS_CUSTOM	3
#define OBEX_TRANS_BLUETOOTH	4
#define OBEX_TRANS_FD		5

/* Standard headers */
#define OBEX_HDR_COUNT		0xc0 /* Number of objects (used by connect) */
#define OBEX_HDR_NAME		0x01 /* Name of the object */
#define OBEX_HDR_TYPE		0x42 /* Type of the object */
#define OBEX_HDR_TIME		0x44 /* Last modification time of (ISO8601) */
#define OBEX_HDR_TIME2		0xC4 /* Deprecated use HDR_TIME instead */
#define OBEX_HDR_LENGTH		0xc3 /* Total lenght of object */
#define OBEX_HDR_DESCRIPTION	0x05 /* Description of object */
#define OBEX_HDR_TARGET		0x46 /* Identifies the target for the object */
#define OBEX_HDR_BODY		0x48 /* Data part of the object */
#define OBEX_HDR_BODY_END	0x49 /* Last data part of the object */
#define OBEX_HDR_WHO		0x4a /* Identifies the sender of the object */
#define OBEX_HDR_APPARAM	0x4c /* Application parameters */
#define OBEX_HDR_AUTHCHAL	0x4d /* Authentication challenge */
#define OBEX_HDR_AUTHRESP	0x4e /* Authentication response */
#define OBEX_HDR_OBJCLASS	0x4f /* OBEX Object class of object */
#define OBEX_HDR_CONNECTION	0xcb /* Connection identifier */

/* Commands */
#define OBEX_CMD_CONNECT	0x00
#define OBEX_CMD_DISCONNECT	0x01
#define OBEX_CMD_PUT		0x02
#define OBEX_CMD_GET		0x03
#define OBEX_CMD_COMMAND	0x04
#define OBEX_CMD_SETPATH	0x05
#define OBEX_CMD_ABORT		0x7f
#define OBEX_FINAL		0x80

/* Responses */
#define	OBEX_RSP_CONTINUE		0x10
#define OBEX_RSP_SWITCH_PRO		0x11
#define OBEX_RSP_SUCCESS		0x20
#define OBEX_RSP_CREATED		0x21
#define OBEX_RSP_ACCEPTED		0x22
#define OBEX_RSP_NO_CONTENT		0x24
#define OBEX_RSP_BAD_REQUEST		0x40
#define OBEX_RSP_UNAUTHORIZED		0x41
#define OBEX_RSP_PAYMENT_REQUIRED	0x42
#define OBEX_RSP_FORBIDDEN		0x43
#define OBEX_RSP_NOT_FOUND		0x44
#define OBEX_RSP_METHOD_NOT_ALLOWED	0x45
#define OBEX_RSP_CONFLICT		0x49
#define OBEX_RSP_INTERNAL_SERVER_ERROR	0x50
#define OBEX_RSP_NOT_IMPLEMENTED	0x51
#define OBEX_RSP_DATABASE_FULL		0x60
#define OBEX_RSP_DATABASE_LOCKED	0x61

/* Min, Max and default transport MTU */
#define OBEX_DEFAULT_MTU	1024
#define OBEX_MINIMUM_MTU	255      
#define OBEX_MAXIMUM_MTU	32768
/* In theory max MTU is (64k-1), but that's quite big. */

/* Optimum MTU for various transport (optimum for throughput).
 * The user/application has to set them via OBEX_SetTransportMTU().
 * If you are worried about safety or latency, stick with the current
 * default... - Jean II */
#define OBEX_IRDA_OPT_MTU	(7 * 2039)	/* 7 IrLAP frames */

#endif
