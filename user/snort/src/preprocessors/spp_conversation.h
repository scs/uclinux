/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __SPP_SESSION_H__
#define __SPP_SESSION_H__

/*******************************************
 * Assigns a conversation pointer to each unique packet
 ********************************************/
#ifndef WIN32
#include <sys/time.h>
#endif /* WIN32 */

#include "mempool.h"
#include "ubi_SplayTree.h"
#include "snort.h"
 
#define CONV_NONE       0x0000
#define CONV_FORWARD    0x0001
#define CONV_REVERSED   0x0002
#define CONV_TALKER_SIP 0x0004
#define CONV_TALKER_DIP 0x0008
#define CONV_MULIPACKETS 0x0010 /* is this an older session */

typedef struct _StateRecord 
{
    ubi_trNode Node; /* used for ubi_ */
    MemBucket *bucket; /* the container that we are in */


    u_int32_t sip;
    u_int32_t dip;
    unsigned short sport;
    unsigned short dport;
    unsigned char ip_proto;  
    
    struct timeval last_time;
    struct timeval first_time;

    /* packet tallys */
    unsigned long bytes_sent;
    unsigned long bytes_recv;

    /* payload tallys */
    unsigned long dsize_sent;
    unsigned long dsize_recv;

    unsigned long pkts_sent;
    unsigned long pkts_recv;

    u_int32_t conv_flags; /* This conversation started out reversed */
} StateRecord;

typedef struct _conversationData 
{
    int isInitialized;
    unsigned int max_convs; /* # of conversations to support @ once */
    unsigned int timeout; /* Number of seconds before we time out */

    MemPool state_records;
    
    ubi_trRoot cache;
    ubi_trRootPtr cachePtr;

    /* lots of the tiny little options */
    char keepstats;
    char alert_odd_protocols;
    char allowed_ip_protocols[256];
    char watch_scans;
    struct timeval prune_time;    
} ConversationData;

void SetupConv(void);
void ConvDelete(StateRecord *sr);

extern ConversationData conv_data;
#endif
