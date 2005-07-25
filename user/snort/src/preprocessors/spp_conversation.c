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

/* $Id$
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "spp_conversation.h"
#include "spp_portscan2.h"

#include "generators.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "parser.h"
#include "mstring.h"
#include "log.h"
#include "detect.h"
#include "event_queue.h"

#define CONV_TIMEOUT 120
#define CONV_DEFAULT_MAX 65335

#define OPT_TIMEOUT "timeout"
#define OPT_MAX_CONV "max_conversations"
#define OPT_ALLOWED_PROTOS "allowed_ip_protocols"
#define OPT_ALERT_BAD_PROTO "alert_odd_protocols"

/* if the conversation is going to be stored this way....
 *
 * Only thing this will really have troubles with is traffic between
 * the same ip
*/

#define PACKET_FORWARD(a) (*((unsigned int*)&a->iph->ip_dst) > *((unsigned int*)&a->iph->ip_src))

#define TRUE 1
#define FALSE 0

/* This INLINE is conflicting with the INLINE defined in bitop.h.
 * So, let's just add a little sanity check here.
 */
#ifdef DEBUG
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE
#else /* DEBUG */
    #ifndef INLINE
        #define INLINE inline
    #endif
#endif

/*********************** exported Global vars *********************/
ConversationData  conv_data;


/***********************Function Declaration*************/
static void ConvInit(u_char* args);
static void ParseConvArgs(u_char* args);
static void ConvFunc(Packet* p);
static int ConvCompareFunc(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr);
static int PruneConvCache(u_int32_t now, int tokill, StateRecord *keeper);
static StateRecord* ConvGetSession(Packet* p);
static INLINE void FillStateRecord(StateRecord *s, Packet *p);
static INLINE void FillConvStats(StateRecord *s, Packet *p);
/****************************************
 *  Register the preprocessor
 ****************************************/
void SetupConv(void)
{
    RegisterPreprocessor("conversation", ConvInit);
    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION, 
                            "Preprocessor: Registering Session\n"););
}

static void ParseConvArgs(u_char* args)
{
    char **toks;
    char **stoks;
    char  *index;
    int num_toks, s_toks;
    int num;

    conv_data.timeout = CONV_TIMEOUT;
    conv_data.max_convs = CONV_DEFAULT_MAX;
    
    if(args == NULL || *args == '\0')
    {
        return;
    }

    /* tokenize the argument list */
    toks = mSplit(args, ",", 31, &num_toks, '\\');

    /* convert the tokens and place them into the port list
       strlen used to easily identify what token - yes a kludge
    */
    for(num = 0; num < num_toks; num++)
    {
        index = toks[num];

        while(index && isspace((int)*(index)))
        {
            index++;
        }
        
        if(!strncasecmp(OPT_TIMEOUT, index, strlen(OPT_TIMEOUT)))
        {
            stoks = mSplit(index, " ", 4, &s_toks, 0);
            if(s_toks < 2)
            {
                FatalError("ERROR %s(%d) => No timeout argument to "
                           "conversation\n", file_name, file_line);
            }

            conv_data.timeout = atoi(stoks[1]);
            mSplitFree(&stoks, s_toks);
        }
        else if(!strncasecmp(OPT_MAX_CONV, index,
                             strlen(OPT_MAX_CONV)))
        {
            stoks = mSplit(index, " ", 4, &s_toks, 0);
            if(s_toks < 2)
            {
                FatalError("ERROR %s(%d) => No max_conversations argument "
                           "to conversation\n", file_name, file_line);
            }

            conv_data.max_convs = atoi(stoks[1]);
            mSplitFree(&stoks, s_toks);
        }
        else if(!strncasecmp(OPT_ALLOWED_PROTOS, index,
                             strlen(OPT_ALLOWED_PROTOS)))
        {
            /* need to sit here and parse through what I will allow
               and what I won't

               defaults to all

               you can specify a list of protocols to support
            */
            char **ports;
            int num_ports;
            char *port;
            int j = 0;
            u_int32_t portnum;

            for(j = 0;j<256;j++)
            {
                conv_data.allowed_ip_protocols[j] = 0;
            }

            ports = mSplit(index, " ", 40, &num_ports, 0);

            if(num_ports < 2)
            {
                FatalError("ERROR %s(%d) => No ip_proto list "
                           "to conversation\n", file_name, file_line);
            }

            j = 1;

            while(j < num_ports)
            {
                port = ports[j];

                if(isdigit((int)port[0]))
                {
                    portnum = atoi(port);

                    if(portnum > 255)
                    {
                        FatalError("ERROR %s(%d) => Bad ip_proto list to "
                                   "conversation\n", file_name, file_line);
                    }

                    conv_data.allowed_ip_protocols[portnum] = 1;
                }
                else if(!strncasecmp(port, "all", 3))
                {
                    memset(&conv_data.allowed_ip_protocols, 1, 256);
                }                
                else
                {
                    FatalError("ERROR %s(%d) => Bad ip_proto list to "
                               "conversation\n", file_name, file_line);
                }

                j++;
            }
            mSplitFree(&ports, num_ports);
        }
        else if(!strncasecmp(OPT_ALERT_BAD_PROTO, index,
                             strlen(OPT_ALERT_BAD_PROTO)))
        {
            conv_data.alert_odd_protocols = 1;
        }        
        else
        {
            FatalError("ERROR %s(%d) => Unknown argument to spp_conversation "
                       "preprocessor: \"%s\"\n", 
                       file_name, file_line, index);
        }
    }   

    mSplitFree(&toks, num_toks);
}

/****************************************
 *  Initialize everything
 ****************************************/
void ConvInit(u_char* args)
{
    int i;
    int printall = 1;
    char buf[STD_BUF+1];
    
    memset(&conv_data, 0, sizeof(ConversationData));
    conv_data.keepstats = 0;
    conv_data.alert_odd_protocols = 0;

    /* allow everything by default */
    memset(&conv_data.allowed_ip_protocols, 1, 256);
    
    ParseConvArgs(args);

    if(mempool_init(&conv_data.state_records,
                    conv_data.max_convs, sizeof(StateRecord)))
    {
        FatalError("ERROR: can't initialize state records\n");
    }

    conv_data.cachePtr = &conv_data.cache;
    
    ubi_trInitTree(conv_data.cachePtr,/* ptr to the tree head */
                   ConvCompareFunc,   /* comparison function */
                   0);                /* don't allow overwrites/duplicates */

    AddFuncToPreprocList(ConvFunc);


    LogMessage("Conversation Config:\n");
    LogMessage("   KeepStats: %d\n", conv_data.keepstats);
    LogMessage("   Conv Count: %d\n", conv_data.max_convs);
    LogMessage("   Timeout   : %d\n", conv_data.timeout);
    LogMessage("   Alert Odd?: %d\n", conv_data.alert_odd_protocols);

    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "   Allowed IP Protocols: ");
    
    for(i=0;i<256;i++) 
    {
        if(!conv_data.allowed_ip_protocols[i])
        {
            printall = 0;
            break;
        }
    }

    if(printall)
    {
        sfsnprintfappend(buf, STD_BUF, " All\n");
    }
    else
    {
        for(i=0;i<256;i++) 
        {
            if(conv_data.allowed_ip_protocols[i])
            {
                sfsnprintfappend(buf, STD_BUF, "%d ", i);
            }
        }
    }
    LogMessage("%s\n", buf);
    
    conv_data.isInitialized = 1;
}

/****************************************
 *  Called for every packet
 ****************************************/
void ConvFunc(Packet* p)
{
    StateRecord* srecord;

    if(!(p->preprocessors & PP_CONVERSATION))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION, 
                    "Ignoring preprocessor conversation\n"););
        return;
    }
    
    if (p->packet_flags & PKT_REBUILT_STREAM) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION, 
                    "Ignoring Rebuilt Stream\n"););
        return;
    }
    
    if (p->iph == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "ignoring non-ip traffic\n"));
        return;
    }

    /* is this an allowed ip protocol */
    if(conv_data.allowed_ip_protocols[p->iph->ip_proto] != 1)
    {
        if(conv_data.alert_odd_protocols == 1)
        {
            SnortEventqAdd(GENERATOR_SPP_CONV, CONV_BAD_IP_PROTOCOL, 
                    1, 0, 5, CONV_BAD_IP_PROTOCOL_STR, 0);
        }
        
        return;
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                            "_____________________________\n"
                            "%s:%u->",
                            inet_ntoa(p->iph->ip_src), p->sp);
               DebugMessage(DEBUG_CONVERSATION, "%s:%u\n",
                            inet_ntoa(p->iph->ip_dst), p->dp););


    /* This will watch portscan watch */
    srecord = ConvGetSession(p);

    /* Let's try to free up some sessions and then assign out some
     *
     * If that doesn't work for what ever reason, return out and mark
     * the conversation header as NULL indicating that we need to do
     * best effort analysis on this packet but we cna't establish it
     * as part of an already existing session
     *
     * would be better to try get, free, alloc, add distinctly to
     * avoid an extra lookup
     *
     */
    if(srecord == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "State table is full! -- %u\n",
                                ubi_trCount(conv_data.cachePtr)););

        
        PruneConvCache(p->pkth->ts.tv_sec, 5, NULL);

        srecord = ConvGetSession(p);
        
        
        if(srecord == NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                    "Can't allocate even after a free\n"););
            // p->state = NULL;
            return;
        }
    }
    
    srecord->last_time.tv_sec = p->pkth->ts.tv_sec;
    srecord->last_time.tv_usec = p->pkth->ts.tv_usec;
    
    if(conv_data.keepstats)
    {
        FillConvStats(srecord, p);
    }

    
    /*
     * controls if we will watch for scans on new sessions with
     * spp_portscan2
     */

    if(conv_data.watch_scans && (!(srecord->conv_flags & CONV_MULIPACKETS)))
    {
        /* only call this if this is the first packet in a conversation */
        psWatch(p);
    }


    if(p->pkth->ts.tv_sec >= (conv_data.prune_time.tv_sec + conv_data.timeout))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION, "Prune time quanta exceeded, pruning "
                                "conversation cache\n"););
        PruneConvCache(p->pkth->ts.tv_sec, 0, NULL);
        conv_data.prune_time.tv_sec = p->pkth->ts.tv_sec;
    }

}

/* Function: StateRecord* ConvAlloc(unsigned long cur_time)
 * 
 * Purpose: get a new state record from
 * Args:
 * 
 * Returns:n
 */ 
StateRecord* ConvAlloc(unsigned long cur_time)
{
    MemBucket* bp;
    StateRecord *sr;
    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION, "Getting free state\n"););

    bp = mempool_alloc(&conv_data.state_records);

    if(bp == NULL)
    {
        
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "State Table is full! used: %u max: %u\n",
                                conv_data.max_convs););
        return NULL;
    }
    
    /* the container has to know what bucket it came from */
    sr = bp->data;
    sr->bucket = bp;

    return sr;    
}

void ConvDelete(StateRecord *sr)
{
    /*
     * need to have a set of call back functions that occur when a
     * conversation is deleted.
     *
     * Eventually, stream4 will be able to delete conversations as
     * well as this one so that someone using the same pair of ports
     * all the time will be detected.  That's why the function is
     * exported.
     */

    MemBucket *mb;

    mb = sr->bucket;

    ubi_sptRemove(conv_data.cachePtr, (ubi_btNodePtr) sr);
    mempool_free(&conv_data.state_records, mb);
}

/* Function: static INLINE void FillConvStats(StateRecord *s, Packet* p)
 * 
 * Purpose: populate the packet data statistics for this conversation
 * Args:
 * 
 * Returns:
 */ 
static INLINE void FillConvStats(StateRecord *s, Packet *p)
{
    if(PACKET_FORWARD(p))
    {
        s->bytes_sent += p->caplen;
        s->dsize_sent += p->dsize;
        s->pkts_sent++;
    }
    else
    {
        s->bytes_recv += p->caplen;
        s->dsize_recv += p->dsize;
        s->pkts_recv++;
    }
}


/***********************************************
 * Fills the state record with info
 ***********************************************/
static INLINE void FillStateRecord(StateRecord* s, Packet* p)
{
    /*
      always store things the same way so that when we have to look
      up a session, we only have to look them up one way.
    */

    s->ip_proto = p->iph->ip_proto;

    if(PACKET_FORWARD(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "going forward!\n"););
        s->sip = p->iph->ip_src.s_addr;
        s->dip = p->iph->ip_dst.s_addr;
        s->sport = p->sp;
        s->dport = p->dp;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "going switcheroo ninja style!\n"););
        s->sip = p->iph->ip_dst.s_addr;
        s->dip = p->iph->ip_src.s_addr;
        s->sport = p->dp;
        s->dport = p->sp;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                            "s->sip: %X, s->dip: %X "
                            "s->sport: %d s->dport: %d s->ip_proto: %d\n",
                            s->sip, s->dip, s->sport,s->dport,s->ip_proto););

    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                            "p->iph->ip_src.s_addr: %X, p->iph->ip_dst.s_addr: %X "
                            "p->sp: %d p->dp: %d p->iph->ip_proto: %d\n",
                            (u_int32_t) p->iph->ip_src.s_addr,
                            (u_int32_t) p->iph->ip_dst.s_addr,
                            p->sp,p->dp,p->iph->ip_proto););


}


/***********************************************
 * Find a session from the hash.
 * returns a pointer to that session.
 * allocates a new session if not found
 ***********************************************/
static StateRecord* ConvGetSession(Packet* p)
{
    /* We should probably only do the look up once and obliterate the
       original session */    
    StateRecord tmp;
    MemBucket *mb = NULL;
    StateRecord *ret = NULL;

    /* FIXME -- this shouldn't be needed */
    bzero(&tmp, sizeof(StateRecord));

    /* Searches it's own junk */
    FillStateRecord(&tmp, p);
    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                            "tmp.sip: %X, tmp.dip: %X "
                            "tmp.sport: %d tmp.dport: %d tmp.ip_proto: %d\n",
                            tmp.sip, tmp.dip, tmp.sport,tmp.dport,tmp.ip_proto););

    
    
    ret = (StateRecord *) ubi_sptFind(conv_data.cachePtr,
                                      (ubi_btItemPtr) &tmp);

    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                            "ret from the sptFind is %p\n", ret););
  
    if(ret == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "Conversation not found... allocating a new one\n"););

        mb = mempool_alloc(&conv_data.state_records);

        if(mb == NULL)
        {
            /* return NULL, free up some conversations, try to assign
               again
            */
            DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                    "mempool is out of state records\n"););
                                    
            return NULL;
        }
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "allocated: %p\n", mb->data););

        
        ret = (StateRecord *) mb->data;
        ret->bucket = mb;

        FillStateRecord(ret, p);
                
        if(ubi_sptInsert(conv_data.cachePtr,
                         (ubi_btNodePtr) ret,
                         (ubi_btNodePtr) ret, NULL) == ubi_trFALSE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                    "insertion into splay tree failed for ret==%p\n", ret););
            return NULL;
        }
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "insertion into splay tree succeed for ret==%p\n", ret););

                       


        /*
	 * When we assign new conversation ID, the greater IP is
	 * always declared to be "sip".  This flag check allows us to
	 * know who was the first talker.
	 */
        
        if(PACKET_FORWARD(p))
        {
            ret->conv_flags |= CONV_FORWARD;
        }
        else
        {
            ret->conv_flags |= CONV_REVERSED;
        }

    }
    else /* ret != NULL */
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "Conversation found @ %p\n", ret););

        ret->conv_flags |= CONV_MULIPACKETS;
    }
    
    return ret;
}

/* Returns -1 if A < B
   Returns 1 if A > B
   Returns 0 if A = B */
static int ConvCompareFunc(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    StateRecord *A = (StateRecord *) ItemPtr;
    StateRecord *B = (StateRecord *) NodePtr;
#ifdef DEBUG

    #define IPLEN 256
    char sip[IPLEN];

    strncpy(sip, inet_ntoa(*(struct in_addr *) &A->sip), IPLEN);
    DebugMessage(DEBUG_PORTSCAN2,"A %d %s:%d -> %s:%d\n",
                 A->ip_proto,
                 sip,
                 A->sport,
                 inet_ntoa(*(struct in_addr *) &A->dip),
                 A->dport);

    strncpy(sip, inet_ntoa(*(struct in_addr *) &B->sip), IPLEN);
    DebugMessage(DEBUG_PORTSCAN2,"B %d %s:%d -> %s:%d\n",
                 B->ip_proto,
                 sip,
                 B->sport,
                 inet_ntoa(*(struct in_addr *) &B->dip),
                 B->dport);

    #undef IPLEN
#endif /* DEBUG */

    

    if(A->sip > B->sip)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,"returning 1\n"););
        return 1;
    }

    if(A->sip < B->sip)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,"returning -1\n"););
        return -1;
    }

    
    if(A->dip > B->dip)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,"returning 1\n"););
        return 1;
    }
    
    if(A->dip < B->dip)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,"returning -1\n"););
        return -1;
    }
    
    /* ok the IPs are equal */
    if(A->sport > B->sport)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,"returning 1\n"););
        return 1;
    }

    
    if(A->sport < B->sport)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,"returning -1, count: %u\n",
                                ubi_trCount(conv_data.cachePtr)
                                ););
        return -1;
    }
    
    if(A->dport > B->dport) return 1;
    if(A->dport < B->dport) return -1;

    /* now lets check the protocol, maybe this should be first but I
       think that most networks only see tcp traffic with a little
       DNS -- cmg
    */

    if(A->ip_proto > B->ip_proto) return 1;
    if(A->ip_proto < B->ip_proto) return -1;

#ifdef DEBUG
    DebugMessage(DEBUG_CONVERSATION, "returning 0 for session equalness\n");

    DebugMessage(DEBUG_CONVERSATION,
                 "A->sip: %u B->sip: %u A->sport: %d"
                 "B->dport: %d A->ip_proto %d B->ip_proto: %d\n",
                 A->sip, B->sip, A->sport, B->sport, A->ip_proto, B->ip_proto
                 );
#endif /* DEBUG */

    return 0;
}

static int PruneConvCache(u_int32_t now, int tokill, StateRecord *keeper)
{
    StateRecord *idx;
    u_int32_t pruned = 0;

    if(ubi_trCount(conv_data.cachePtr) <= 1)
    {
        return 0;
    }

    /* Number of things that need to be deleted */
    if(tokill == 0)
    {
        idx = (StateRecord *) ubi_btFirst((ubi_btNodePtr)conv_data.cachePtr->root);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            if(idx == keeper)
            {
                idx = (StateRecord *) ubi_btNext((ubi_btNodePtr)idx);
                continue;
            }

            if((idx->last_time.tv_sec+conv_data.timeout) < now)
            {
                StateRecord *savidx = idx;

                if(ubi_trCount(conv_data.cachePtr) > 1)
                {
                    idx = (StateRecord *) ubi_btNext((ubi_btNodePtr)idx);
                    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                            "pruning stale conversation\n"););
                    ConvDelete(savidx);
                    pruned++;
                }
                else
                {
                    ConvDelete(savidx);
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                if(idx != NULL && ubi_trCount(conv_data.cachePtr))
                {
                    idx = (StateRecord *) ubi_btNext((ubi_btNodePtr)idx);
                }
                else
                {
                    return pruned;
                }
            }
        } while(idx != NULL);

        return pruned;
    }
    else
    {
        while(tokill-- &&  ubi_trCount(conv_data.cachePtr) > 1)
        {
            idx = (StateRecord *) ubi_btLeafNode((ubi_btNodePtr)conv_data.cachePtr);
            if(idx != keeper)
                ConvDelete(idx);
        }
#ifdef DEBUG
        if(tokill > 0)
        {
            DebugMessage(DEBUG_STREAM, "Emptied out the conversation cache"
                         "completely tokill: %d\n",
                         tokill);
        }
#endif /* DEBUG */

        return 0;
    }

    return 0;
}

