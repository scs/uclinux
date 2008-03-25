/*********************************************************************
 *                
 * Filename:      netbuf.c
 * Version:       0.9
 * Description:   Network buffer handling routines. 
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Fri Mar 19 09:07:21 1999
 * Modified at:   Sat Oct 16 14:53:39 1999
 * Modified by:   Dag Brattli <dagb@cs.uit.no>
 * Sources:       skbuff.c by  Alan Cox <iiitac@pyr.swan.ac.uk> and
 *                             Florian La Roche <rzsfl@rz.uni-sb.de>
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *     
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License 
 *     along with this program; if not, write to the Free Software 
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 *     MA 02111-1307 USA
 *     
 ********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef OBEX_SYSLOG
#include <syslog.h>
#endif

#include <netbuf.h>

/*
 * Function msg_recycle (msg)
 *
 *    Reuse an already used message. We just reset the state
 *
 */
GNetBuf *g_netbuf_recycle(GNetBuf *msg)
{
	msg->data = msg->head;
	msg->tail = msg->head;
	msg->len = 0;
	msg->end = msg->head + msg->truesize;

	return msg;
}

/*
 * Function g_netbuf_new (len)
 *
 *    Allocate new network buffer
 *
 */
GNetBuf *g_netbuf_new(unsigned int len)
{
	GNetBuf *msg;
	uint8_t *buf;
	
	msg = malloc(sizeof(GNetBuf));
	if (msg == NULL)
		return NULL;
	memset(msg, 0, sizeof(GNetBuf));
	
	buf = malloc(len);
	if (buf == NULL) {
		free(msg);
		return NULL;
	}
	
	/* Init */
	msg->truesize = len;
	msg->head = buf;
	
	g_netbuf_recycle(msg);
	
	return msg;
}

/*
 * Function g_netbuf_realloc (msg, len)
 *
 *    Change the true size of the message
 *
 */
GNetBuf *g_netbuf_realloc(GNetBuf *msg, unsigned int len)
{
	uint8_t *buf;

/* 	DEBUG(4, "msg->head=%p\n", msg->head); */
/* 	DEBUG(4, "msg->data=%p\n", msg->data); */
/* 	DEBUG(4, "msg->tail=%p\n", msg->tail); */
/* 	DEBUG(4, "msg->len=%d\n", msg->len); */
/* 	DEBUG(4, "msg->truesize=%d\n\n", msg->truesize); */

	buf = realloc(msg->head, len);
	if (buf == NULL)
		return NULL;

	msg->truesize = len;
	msg->data = buf + (msg->data - msg->head);	
	msg->tail = buf + (msg->tail - msg->head);
	msg->head = buf;
	msg->end = msg->head + len;

/* 	DEBUG(4, "msg->head=%p\n", msg->head); */
/* 	DEBUG(4, "msg->data=%p\n", msg->data); */
/* 	DEBUG(4, "msg->tail=%p\n", msg->tail); */
/* 	DEBUG(4, "msg->len=%d\n", msg->len); */
/* 	DEBUG(4, "msg->truesize=%d\n", msg->truesize); */

	return msg;
}

/*
 * Function g_netbuf_free (msg)
 *
 *    Free message
 *
 */
void g_netbuf_free(GNetBuf *msg)
{
	if (!msg)
		return;
	if (msg->head)
		free(msg->head);
	free(msg);
}

/*
 * Function g_netbuf_put (msg, len)
 *
 *    Make space for more data into message
 *
 */
uint8_t *g_netbuf_put(GNetBuf *msg, unsigned int len)
{
        uint8_t *tmp = msg->tail;
        
	msg->tail += len;
        msg->len += len;
	
        if (msg->tail > msg->end) {
		//DEBUG(4, "put over, trying to realloc ...!\n");
		
		msg = g_netbuf_realloc(msg, msg->truesize+len);
		if (!msg)
			return NULL;

		tmp = msg->tail - len;
        }
        return tmp;
}

uint8_t *g_netbuf_put_data(GNetBuf *msg, uint8_t *data, unsigned int len)
{
	uint8_t *tmp;

	/* Make room for more data */
	tmp = g_netbuf_put(msg, len);

	/* Copy body data to object */
	memcpy(tmp, data, len);

	return tmp;
}

/*
 * Function g_netbuf_push (buf, len)
 *
 *    Insert new header in front of data
 *
 */
uint8_t *g_netbuf_push(GNetBuf *msg, unsigned int len)
{
	if ((msg->data - len) < msg->head) {
		//DEBUG(4, "pushed under, trying to realloc!\n");

		msg = g_netbuf_realloc(msg, msg->truesize+len);
		if (!msg)
			return NULL;
		
		/* Move data with offset len */
		memmove(msg->data+len, msg->data, msg->len);
		msg->data = msg->data+len;
		msg->tail = msg->tail+len;
	}

	msg->data -= len;
	msg->len += len;

	return msg->data;
}

/*
 * Function g_netbuf_prepend_hdr (msg, hdr, len)
 *
 *    
 *
 */
uint8_t *g_netbuf_prepend_hdr(GNetBuf *msg, uint8_t *hdr, unsigned int len)
{
	uint8_t *tmp;
	
	/* Make room for header */
	tmp = g_netbuf_push(msg, len);

	/* Copy body data to object */
	memcpy(tmp, hdr, len);

	return tmp;
}

/*
 * Function g_netbuf_pull (msg, len)
 *
 *    Remove header or data in front of the message
 *
 */
uint8_t *g_netbuf_pull(GNetBuf *msg, unsigned int len)
{
	if (len > msg->len)
                return NULL;
	
	msg->len -= len;
        return msg->data += len;
}

/*
 * Function g_netbuf_reserve (msg, len)
 *
 *    Reserve space in front of message for headers or data
 *
 */
void g_netbuf_reserve(GNetBuf *msg, unsigned int len)
{
        msg->data+=len;
        msg->tail+=len;
}

/*
 * Function msg_headroom (msg)
 *
 *    Returns the number of bytes available for inserting headers or data
 *    in front of the message.
 */
int g_netbuf_headroom(GNetBuf *msg)
{
	return msg->data - msg->head;
}

/*
 * Function g_netbuf_tailroom (msg)
 *
 *    Returns the number of bytes available for inserting more data into the
 *    message
 */
int g_netbuf_tailroom(GNetBuf *msg)
{
	return msg->end - msg->tail;
}

/*
 * Function g_netbuf_trim (msg, len)
 *
 *    Set the length of the message
 *
 */
void g_netbuf_trim(GNetBuf *msg, unsigned int len)
{
	if (msg->len > len) {
		msg->len = len;
		msg->tail = msg->data+len;
        }
}

void g_netbuf_print(const char *label, GNetBuf *msg)
{
	int 	i;
	int	j = -1;
	char	buf[81];

	for (i = 0; i < msg->len; i++) {
		j = (i % 16) * 3;
		sprintf(&(buf[j]), "%02x ", msg->data[i]);
		if((j == (15 * 3)) || (i == (msg->len - 1))) {
#ifdef OBEX_SYSLOG
			syslog(LOG_DEBUG, "OpenObex: %s: %s\n", label, buf);
#else
			fprintf(stderr, "%s: %s\n", label, buf);
#endif
		}
	}
}


/* slist_t */

slist_t *slist_append(slist_t *list, void *data)
{
	slist_t	*entry, *prev;

	entry = (slist_t*)malloc(sizeof(slist_t));
	if (!entry)
		return NULL;
	entry->data = data;
	entry->next = NULL;
	
	if (!list)
		return entry;
	
	for (prev = list; prev->next; prev = prev->next) ;
	
	prev->next = entry;
	return list;
}

slist_t *slist_remove(slist_t *list, void *data)
{
	slist_t	*entry, *prev;

	for (prev = NULL, entry = list; entry; prev = entry, entry = entry->next) {
		if (entry->data == data) {
			if (prev)
				prev->next = entry->next;
			else
				list = entry->next;
			free(entry);
			break;
		}
	}
	return list;
}



