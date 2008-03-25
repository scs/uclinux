/*********************************************************************
 *                
 * Filename:      gnetbuf.h
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Fri Mar 19 09:06:47 1999
 * Modified at:   Tue Sep  7 22:38:59 1999
 * Modified by:   Dag Brattli <dagb@cs.uit.no>
 * Sources:       skbuff.h by  Alan Cox <iiitac@pyr.swan.ac.uk> and
 *                             Florian La Roche <rzsfl@rz.uni-sb.de>
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *      
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version.
 *  
 *     Neither Dag Brattli nor University of Tromsø admit liability nor
 *     provide warranty for any of this software. This material is 
 *     provided "AS-IS" and at no charge.
 *     
 *     This code is very inspired by skbuff.h, and this is how it work:
 *
 *     |<------------ truesize ----------------->|
 *      ------------------------------------------
 *     | headroom |       len       | tailroom   |
 *      ------------------------------------------
 *     ^          ^                 ^            ^
 *     |          |                 |            |
 *    head       data              tail         end
 *
 ********************************************************************/

#ifndef G_NETBUF_H
#define G_NETBUF_H

#include <stdint.h>

typedef struct _slist_t{
	void		*data;
	struct _slist_t	*next;
} slist_t;

typedef struct _GNetBuf GNetBuf;

struct _GNetBuf {
	uint8_t *data;   /* Pointer to the actual data */
	uint8_t *head;   /* Pointer to start of buffer */
	uint8_t *tail;   /* Pointer to end of data */
	uint8_t *end;    /* Pointer to end of buffer */
	unsigned int len;      /* Length of data */
	unsigned int truesize; /* Real size of the buffer */
};

GNetBuf *g_netbuf_new(unsigned int len);
GNetBuf *g_netbuf_realloc(GNetBuf *buf, unsigned int len);
void     g_netbuf_free(GNetBuf *msg);
GNetBuf *g_netbuf_recycle(GNetBuf *msg);
uint8_t   *g_netbuf_put(GNetBuf *msg, unsigned int len);
uint8_t   *g_netbuf_put_data(GNetBuf *msg, uint8_t *data, unsigned int len);
uint8_t   *g_netbuf_push(GNetBuf *msg, unsigned int len);
uint8_t   *g_netbuf_pull(GNetBuf *msg, unsigned int len);
void     g_netbuf_reserve(GNetBuf *msg, unsigned int len);
int      g_netbuf_headroom(GNetBuf *msg);
int      g_netbuf_tailroom(GNetBuf *msg);
void     g_netbuf_set_size(GNetBuf *msg, unsigned int len);
void     g_netbuf_print(const char *fname, GNetBuf *msg);

static inline uint8_t *g_netbuf_get_data(GNetBuf *msg) { return msg->data; }
static inline uint8_t g_netbuf_get_len(GNetBuf *msg) { return msg->len; }

slist_t *slist_append(slist_t *list, void *data);
slist_t *slist_remove(slist_t *list, void *data);

#endif



