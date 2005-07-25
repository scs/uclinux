/* $Id$ */

/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2003 Sourcefire, Inc.
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

/* spp_stream4 
 * 
 * Purpose: Stateful inspection and tcp stream reassembly in Snort
 *
 * Arguments:
 *   
 * Effect:
 *
 * Comments:
 *
 * Any comments?
 *
 */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef DEBUG
    #ifndef INLINE
        #define INLINE inline
    #endif
#else
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE   
#endif /* DEBUG */


#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */
#include <time.h>
#include <rpc/types.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "bounds.h"
#include "decode.h"
#include "event.h"
#include "debug.h"
#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "mstring.h"
#include "checksum.h"
#include "log.h"
#include "generators.h"
#include "detect.h"
#include "perf.h"
#include "timersub.h"
#include "ubi_SplayTree.h"
#include "snort.h"
#include "stream.h"
#include "snort_packet_header.h"
#include "event_queue.h"
#include "inline.h"

/*  D E F I N E S  **************************************************/

/* normal TCP states */
#define CLOSED       0
#define LISTEN       1
#define SYN_RCVD     2
#define SYN_SENT     3
#define ESTABLISHED  4
#define CLOSE_WAIT   5
#define LAST_ACK     6
#define FIN_WAIT_1   7
#define CLOSING      8
#define FIN_WAIT_2   9
#define TIME_WAIT   10

/* extended states for fun stuff */
#define NMAP_FINGERPRINT_2S         30
#define NMAP_FINGERPRINT_NULL       31
#define NMAP_FINGERPRINT_UPSF       32
#define NMAP_FINGERPRINT_ZERO_ACK   33

#define ACTION_NOTHING                  0x00000000
#define ACTION_FLUSH_SERVER_STREAM      0x00000001
#define ACTION_FLUSH_CLIENT_STREAM      0x00000002
#define ACTION_DROP_SESSION             0x00000004
#define ACTION_ACK_SERVER_DATA          0x00000008
#define ACTION_ACK_CLIENT_DATA          0x00000010
#define ACTION_DATA_ON_SYN              0x00000020
#define ACTION_SET_SERVER_ISN           0x00000040
#define ACTION_COMPLETE_TWH             0x00000080
#define ACTION_ALERT_NMAP_FINGERPRINT   0x00000100
#define ACTION_INC_PORT                 0x00000200

#define SERVER_PACKET   0
#define CLIENT_PACKET   1

#define FROM_SERVER     0
#define FROM_CLIENT     1

#define PRUNE_QUANTA    30              /* seconds to timeout a session */
#define STREAM4_MEMORY_CAP     8388608  /* 8MB */
#define STREAM4_TTL_LIMIT 5             /* default for TTL Limit */
#define DEFAULT_STREAM_TRACKERS 256000  /* 256k sessions by default */

#define STATS_HUMAN_READABLE   1
#define STATS_MACHINE_READABLE 2
#define STATS_BINARY           3

#define STATS_MAGIC  0xDEAD029A   /* magic for the binary stats file */

#define REVERSE     0
#define NO_REVERSE  1

#define METHOD_FAVOR_NEW  0x01
#define METHOD_FAVOR_OLD  0x02

/* # of packets that we accept on an unestab conn */
#define UNESTABLISHED_MAX_PCOUNT 300

/* what pcap can hold is how this limit comes about -- cmg */
#define MAX_STREAM_SIZE (IP_MAXPACKET - IP_HEADER_LEN - TCP_HEADER_LEN - ETHERNET_HEADER_LEN) 

/* Macros to deal with sequence numbers - p810 TCP Illustrated vol 2 */
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)

#define NO_CHK_SEQ  0
#define CHK_SEQ     1


/* these are needed in snort versions before 2.0build something */
#ifndef SNORT_20
extern char *file_name;
extern int *file_line;
#endif /* SNORT_20 */


/* We must twiddle to align the offset the ethernet header and align
   the IP header on solaris -- maybe this will work on HPUX too.
*/
#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif

/* values for the smartbits detector/self perservation */
#define SELF_PRES_THRESHOLD        50
#define SELF_PRES_PERIOD           90

#define SUSPEND_THRESHOLD   200
#define SUSPEND_PERIOD      30

#define OPS_NORMAL              0
#define OPS_SELF_PRESERVATION   1
#define OPS_SUSPEND             2

#define MAXSIZE_IP              65535
#define MAX_TRACKER_AMOUNT      (MAX_STREAM_SIZE + 4000)


/* random array of flush points */

#define FCOUNT 64

static u_int8_t flush_points[FCOUNT] = { 128, 217, 189, 130, 240, 221, 134, 129,
                                         250, 232, 141, 131, 144, 177, 201, 130,
                                         230, 190, 177, 142, 130, 200, 173, 129,
                                         250, 244, 174, 151, 201, 190, 180, 198,
                                         220, 201, 142, 185, 219, 129, 194, 140,
                                         145, 191, 197, 183, 199, 220, 231, 245,
                                         233, 135, 143, 158, 174, 194, 200, 180,
                                         201, 142, 153, 187, 173, 199, 143, 201 };

#ifdef DEBUG
static char *state_names[] = { "CLOSED",
                              "LISTEN",
                              "SYN_RCVD",
                              "SYN_SENT",
                              "ESTABLISHED",
                              "CLOSE_WAIT",
                              "LAST_ACK",
                              "FIN_WAIT_1",
                              "CLOSING",
                              "FIN_WAIT_2",
                              "TIME_WAIT"};
#endif

/*  D A T A   S T R U C T U R E S  **********************************/
typedef struct _BuildData
{
    Stream *stream;
    u_int8_t *buf;
    u_int32_t total_size;
    /* u_int32_t build_flags; -- reserved for the day when we generate 1 stream event and log the stream */
} BuildData;

typedef struct _BinStats
{
    u_int32_t start_time;
    u_int32_t end_time;
    u_int32_t sip;
    u_int32_t cip;
    u_int16_t sport;
    u_int16_t cport;
    u_int32_t spackets;
    u_int32_t cpackets;
    u_int32_t sbytes;
    u_int32_t cbytes;
} BinStats;

typedef struct _StatsLog
{
    FILE *fp;
    char *filename;

} StatsLog;

typedef struct _StatsLogHeader
{
    u_int32_t magic;
    u_int32_t version_major;
    u_int32_t version_minor;
    u_int32_t timezone;
} StatsLogHeader;

typedef struct _S4Emergency
{
    u_int32_t end_time;
    char old_reassemble_client;
    char old_reassemble_server;
    char old_reassembly_alerts;
    int old_assurance_mode;
    char old_stateful_mode;
    int new_session_count;
    int status;
} S4Emergency;

typedef struct _StreamKey
{
    u_int32_t sip;
    u_int32_t cip;
    u_int16_t sport;
    u_int16_t cport;
} STREAM_KEY;

typedef Session *SessionPtr;

StatsLog *stats_log;

/* splay tree root data */
static ubi_trRoot s_cache;
static ubi_trRootPtr RootPtr = &s_cache;

u_int32_t safe_alloc_faults;

/* we keep a stream packet queued up and ready to go for reassembly */
Packet *stream_pkt;

/*  G L O B A L S  **************************************************/

extern int do_detect;

/* external globals from rules.c */
FILE *session_log;
Stream4Data s4data;
u_int32_t stream4_memory_usage;
u_int32_t ps_memory_usage;

/* stream4 emergency mode counters... */
S4Emergency s4_emergency;

/*  P R O T O T Y P E S  ********************************************/
void *SafeAlloc(unsigned long, int, Session *);
void ParseStream4Args(char *);
void Stream4InitReassembler(u_char *);
void ReassembleStream4(Packet *);
Session *GetSession(Packet *);
Session *CreateNewSession(Packet *, u_int32_t, u_int32_t);
void DropSession(Session *);
void DeleteSession(Session *, u_int32_t);
void DeleteSpd(ubi_trRootPtr);
int GetDirection(Session *, Packet *);
void Stream4CleanExitFunction(int, void *);
void Stream4RestartFunction(int, void *);
void PrintSessionCache();
int CheckRst(Session *, int, u_int32_t, Packet *);
int PruneSessionCache(u_int32_t, int, Session *);
void StoreStreamPkt(Session *, Packet *, u_int32_t);
void FlushStream(Stream *, Packet *, int);
void InitStream4Pkt();
int BuildPacket(Stream *, u_int32_t, Packet *, int);
int CheckPorts(u_int16_t, u_int16_t);
void PortscanWatch(Session *, u_int32_t);
void PortscanDeclare(Packet *);
void AddNewTarget(ubi_trRootPtr, u_int32_t, u_int16_t, u_int8_t);
void AddNewPort(ubi_trRootPtr, u_int16_t, u_int8_t);
int LogStream(Stream *);
void WriteSsnStats(BinStats *);
void OpenStatsFile();
static int RetransTooFast(struct timeval *old, struct timeval *new);
void Stream4Init(u_char *);
void PreprocFunction(Packet *);
void PreprocRestartFunction(int);
void PreprocCleanExitFunction(int);
static INLINE int isBetween(u_int32_t low, u_int32_t high, u_int32_t cur);
static INLINE int NotForStream4(Packet *p);
static INLINE int SetFinSent(Packet *p, Session *ssn, int direction);
static INLINE int WithinSessionLimits(Packet *p, Stream *stream);

 /* helpers for dealing with session byte_counters */
static INLINE void StreamSegmentSub(Stream *stream, u_int16_t sub);
static INLINE void StreamSegmentAdd(Stream *stream, u_int16_t add);

/*
  Here is where we separate which functions will be called in the
  normal case versus in the asynchronus state

*/
   
int UpdateState(Session *, Packet *, u_int32_t); 
int UpdateState2(Session *, Packet *, u_int32_t); 
int UpdateStateAsync(Session *, Packet *, u_int32_t);

static void TcpAction(Session *ssn, Packet *p, int action, int direction, 
                      u_int32_t pkt_seq, u_int32_t pkt_ack);
static void TcpActionAsync(Session *ssn, Packet *p, int action, int direction, 
                           u_int32_t pkt_seq, u_int32_t pkt_ack);



/** 
 * See if a sequence number is in range.
 * 
 * @param low base sequence number
 * @param high acknowledged sequence number
 * @param cur sequence number to check
 * 
 * @return 1 if we are between these sequence numbers, 0 otherwise
 */
static INLINE int isBetween(u_int32_t low, u_int32_t high, u_int32_t cur)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"(%u,%u,%u) = (low, high, cur)\n",
                low,high,cur););
    return (cur - low) <= (high - low);
}


static int CompareFunc(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    Session *nSession;
    Session *iSession; 

    nSession = ((Session *)NodePtr);
    iSession = (Session *)ItemPtr;

    if(nSession->server.ip < iSession->server.ip) return 1;
    else if(nSession->server.ip > iSession->server.ip) return -1;

    if(nSession->client.ip < iSession->client.ip) return 1;
    else if(nSession->client.ip > iSession->client.ip) return -1;
        
    if(nSession->server.port < iSession->server.port) return 1;
    else if(nSession->server.port > iSession->server.port) return -1;

    if(nSession->client.port < iSession->client.port) return 1;
    else if(nSession->client.port > iSession->client.port) return -1;

    return 0;
}


/** 
 * Check to if retransmissions are occuring too quickly
 * 
 * @param old previous timeval
 * @param cur current timeval
 * 
 * @return 1 if the Retransmission is too quick, 0 if it's ok
 */
static int RetransTooFast(struct timeval *old, struct timeval *cur)
{
    struct timeval diff;

    TIMERSUB(cur, old, &diff);

    /* require retransmissions wait atleast 1.1s */
    if(diff.tv_sec > 1)
        return 0;
    else if(diff.tv_sec == 1 && diff.tv_usec > 100)
        return 0;
        
    return 1;
}

static int DataCompareFunc(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    StreamPacketData *nStream;
    StreamPacketData *iStream; 

    nStream = ((StreamPacketData *)NodePtr);
    iStream = ((StreamPacketData *)ItemPtr);

    if(nStream->seq_num < iStream->seq_num) return 1;
    else if(nStream->seq_num > iStream->seq_num) return -1;

    return 0;
}

static void KillSpd(ubi_trNodePtr NodePtr)
{
    StreamPacketData *tmp;

    tmp = (StreamPacketData *)NodePtr;

    stream4_memory_usage -= tmp->pkt_size;
    free(tmp->pkt);

    stream4_memory_usage -= sizeof(StreamPacketData);
    free(tmp);
}


static void TraverseFunc(ubi_trNodePtr NodePtr, void *build_data)
{
    Stream *s;
    StreamPacketData *spd;
    BuildData *bd;
    u_int8_t *buf;
    int trunc_size;
    int offset = 0;

    if(s4data.stop_traverse)
        return;

    spd = (StreamPacketData *) NodePtr;
    bd = (BuildData *) build_data;
    s = bd->stream;
    buf = bd->buf;

    /* Don't reassemble if there's nothing to reassemble.
     * The first two cases can probably never happen. I personally
     * prefer strong error checking (read: paranoia).
     */
    if(spd->payload_size == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "not reassembling because "
                    "the payload size is zero.\n"););
        spd->chuck = SEG_FULL;
        return;
    }
    else if(SEQ_EQ(s->base_seq, s->last_ack))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "not reassembling because "
                    "base_seq = last_ack (%u).\n", s->base_seq););
        return;
    }

    /* Packet is completely before the current window. */
    else if(SEQ_LEQ(spd->seq_num, s->base_seq) &&
            SEQ_LEQ(spd->seq_num + spd->payload_size, s->base_seq))
    {
        /* ignore this segment, we've already looked at it */
        spd->chuck = SEG_FULL;
        return;
    }
    /* Packet starts outside the window and ends inside it. */
    else if(SEQ_LT(spd->seq_num, s->base_seq) &&
            isBetween(s->base_seq+1, s->last_ack, (spd->seq_num + spd->payload_size)))
    {
        /* case where we've got a segment that wasn't completely ack'd 
         * last time it was processed, do a partial copy into the buffer
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Incompleted segment, copying up "
                    "to last-ack\n"););

        /* calculate how much un-ack'd data to copy */
        trunc_size = (spd->seq_num+spd->payload_size) - s->base_seq;

        /* figure out where in the original data payload to start copying */
        offset = s->base_seq - spd->seq_num;

        if(trunc_size < 65500 && trunc_size > 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Copying %d bytes into buffer, "
                        "offset %d, buf %p\n", trunc_size, offset, 
                        buf););
            SafeMemcpy(buf, spd->payload+offset, trunc_size,
                    stream_pkt->data, stream_pkt->data + MAX_STREAM_SIZE);            
            pc.rebuilt_segs++;
            bd->total_size += trunc_size;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Woah, got bad TCP segment "
                        "trunctation value (%d)\n", trunc_size););
        }

        spd->chuck = SEG_FULL;
    }
    /* if it's in bounds... */
    else if(isBetween(s->base_seq, s->last_ack-1, spd->seq_num) &&
            isBetween(s->base_seq, s->last_ack, (spd->seq_num + spd->payload_size)))
    {
        offset = spd->seq_num - s->base_seq;

        s->next_seq = spd->seq_num + spd->payload_size;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Copying %d bytes into buffer, "
                    "offset %d, buf %p\n", spd->payload_size, offset, 
                    buf););

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "spd->seq_num (%u)  s->last_ack (%u) "
                    "s->base_seq(%u) size: (%u) s->next_seq(%u), "
                    "offset(%u), MAX(%u)\n",
                    spd->seq_num, s->last_ack, s->base_seq,
                    spd->payload_size, s->next_seq, offset, 
                    MAX_STREAM_SIZE));

        SafeMemcpy(buf+offset, spd->payload, spd->payload_size,
                stream_pkt->data, stream_pkt->data + MAX_STREAM_SIZE);

        pc.rebuilt_segs++;

        spd->chuck = SEG_FULL;
        bd->total_size += spd->payload_size;
    } 
    else if(isBetween(s->base_seq, s->last_ack-1, spd->seq_num) &&
            SEQ_GT((spd->seq_num + spd->payload_size), s->last_ack))
    {
        /*
         *  if it starts in bounds and hasn't been completely ack'd, 
         *  truncate the last piece and copy it in 
         */
        trunc_size = s->last_ack - spd->seq_num; 

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Truncating overlap of %d bytes\n", 
                    spd->seq_num + spd->payload_size - s->last_ack);
                DebugMessage(DEBUG_STREAM, "    => trunc info seq: 0x%X   "
                    "size: %d  last_ack: 0x%X\n", 
                    spd->seq_num, spd->payload_size, s->last_ack);
                );

        offset = spd->seq_num - s->base_seq;

        if(trunc_size < (65500-offset) && trunc_size > 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Copying %d bytes into buffer, "
                        "offset %d, buf %p\n", trunc_size, offset, 
                        buf););
            SafeMemcpy(buf+offset, spd->payload, trunc_size,
                    stream_pkt->data, stream_pkt->data + MAX_STREAM_SIZE);            
            pc.rebuilt_segs++;
            bd->total_size += trunc_size;
            spd->chuck = SEG_PARTIAL;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Woah, got bad TCP segment "
                        "trunctation value (%d)\n", trunc_size););
        }
    }
    else if(SEQ_GEQ(spd->seq_num,s->last_ack))
    {
        /* we're all done, we've walked past the end of the ACK'd data */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                    "   => Segment is past last ack'd data, "
                    "ignoring for now...\n");
                DebugMessage(DEBUG_STREAM,  "        => (%d bytes @ seq 0x%X, "
                    "ack: 0x%X)\n", spd->payload_size, spd->seq_num, s->last_ack);
                );

        /* since we're reassembling in order, once we hit an overflow condition
         * let's stop trying for now
         */
        s4data.stop_traverse = 1;
        //s4data.stop_seq = spd->seq_num;
        s4data.stop_seq = s->last_ack;
    }
    else
    {
        /* The only case that should reach this point is if
         * spd->seq_num < s->base_seq &&
         * spd->seq_num + spd->payload_size >= s->last_ack
         * Can that ever happen?
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Ended up in the default case somehow.. !\n"
                    "spd->seq_num(%u) spd->payload_size(%u)\n",
                    spd->seq_num, spd->payload_size););        
    }
} 

void SegmentCleanTraverse(Stream *s)
{
    StreamPacketData *spd;
    StreamPacketData *foo;

    spd = (StreamPacketData *) ubi_btFirst((ubi_btNodePtr)&s->data);

    while(spd != NULL)
    {
        if(spd->chuck == SEG_FULL || SEQ_GEQ(s->last_ack,(spd->seq_num+spd->payload_size)))
        {
            StreamPacketData *savspd = spd;
            spd = (StreamPacketData *) ubi_btNext((ubi_btNodePtr)spd);
#ifdef DEBUG
            if(savspd->chuck == SEG_FULL)
            {
                DebugMessage(DEBUG_STREAM, "[sct] chucking used segment\n");
            }
            else
            {
                DebugMessage(DEBUG_STREAM, "[sct] tossing unused segment\n");
            }
#endif /*DEBUG*/
            foo = (StreamPacketData *) ubi_sptRemove(&s->data, 
                    (ubi_btNodePtr) savspd);
            StreamSegmentSub(s, foo->payload_size);

            stream4_memory_usage -= foo->pkt_size;
            free(foo->pkt);
            stream4_memory_usage -= sizeof(StreamPacketData);
            free(foo);
        }
        else
        {
            spd = (StreamPacketData *) ubi_btNext((ubi_btNodePtr)spd);
        }
    }
}

/* XXX: this will be removed as we clean up the modularization */
void DirectLogTcpdump(struct pcap_pkthdr *, u_int8_t *);

static void LogTraverse(ubi_trNodePtr NodePtr, void *foo)
{
    StreamPacketData *spd;

    spd = (StreamPacketData *) NodePtr;
    /* XXX: modularization violation */
    DirectLogTcpdump((struct pcap_pkthdr *)&spd->pkth, spd->pkt); 
}



void *SafeAlloc(unsigned long size, int tv_sec, Session *ssn)
{
    void *tmp;

    stream4_memory_usage += size;

    /* if we use up all of our RAM, try to free up some stale sessions */
    if(stream4_memory_usage > s4data.memcap)
    {
        pc.str_mem_faults++;
        sfPerf.sfBase.iStreamFaults++;
        if(!PruneSessionCache((u_int32_t)tv_sec, 0, ssn))
        {
            /* if we can't prune due to time, just nuke 5 random sessions */
            PruneSessionCache(0, 5, ssn);            
        }
    }

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate memory! (%lu bytes in use)\n", 
                   (unsigned long)stream4_memory_usage);
    }

    return tmp;
}


/*
 * Function: SetupStream4()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 */
void SetupStream4()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterPreprocessor("stream4", Stream4Init);
    RegisterPreprocessor("stream4_reassemble", Stream4InitReassembler);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "Preprocessor: Stream4 is setup...\n"););
}


/*
 * Function: Stream4Init(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 */
void Stream4Init(u_char *args)
{
    char logfile[STD_BUF];

    s4data.stream4_active = 1;
    pv.stateful = 1;
    s4data.memcap = STREAM4_MEMORY_CAP;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "log_dir is %s\n", pv.log_dir););

    /* initialize the self preservation counters */
    s4data.sp_threshold      = SELF_PRES_THRESHOLD;
    s4data.sp_period         = SELF_PRES_PERIOD;
    s4data.suspend_threshold = SUSPEND_THRESHOLD;
    s4data.suspend_period    = SUSPEND_PERIOD;
    s4data.state_protection  = 0; 
    
    s4_emergency.end_time = 0;
    s4_emergency.new_session_count = 0;
    s4_emergency.status = OPS_NORMAL;
   
    /* parse the argument list from the rules file */
    ParseStream4Args(args);

    snprintf(logfile, STD_BUF, "%s/%s", pv.log_dir, "session.log");
    
    if(s4data.track_stats_flag)
    {
        if((session_log = fopen(logfile, "a+")) == NULL)
        {
            FatalError("Unable to write to \"%s\": %s\n", logfile, 
                       strerror(errno));
        }
    }

    s4data.last_prune_time = 0;
    
    stream_pkt = (Packet *) SafeAlloc(sizeof(Packet), 0, NULL);

    InitStream4Pkt();

    /* tell the rest of the program that we're stateful */
    snort_runtime.capabilities.stateful_inspection = 1;
    
    (void)ubi_trInitTree(RootPtr,       /* ptr to the tree head */
                         CompareFunc,   /* comparison function */
                         0);            /* don't allow overwrites/duplicates */

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "Preprocessor: Stream4 Initialized\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(ReassembleStream4);
    AddFuncToCleanExitList(Stream4CleanExitFunction, NULL);
    AddFuncToRestartList(Stream4RestartFunction, NULL);    
}

void DisplayStream4Config(void) 
{
    LogMessage("Stream4 config:\n");
    LogMessage("    Stateful inspection: %s\n", 
               s4data.stateful_inspection_flag ? "ACTIVE": "INACTIVE");
    LogMessage("    Session statistics: %s\n", 
               s4data.track_stats_flag ? "ACTIVE":"INACTIVE");
    LogMessage("    Session timeout: %d seconds\n", s4data.timeout);
    LogMessage("    Session memory cap: %lu bytes\n", (unsigned long)s4data.memcap);
    LogMessage("    State alerts: %s\n", 
               s4data.state_alerts ? "ACTIVE":"INACTIVE");
    LogMessage("    Evasion alerts: %s\n", 
               s4data.evasion_alerts ? "ACTIVE":"INACTIVE");
    LogMessage("    Scan alerts: %s\n", 
               s4data.ps_alerts ? "ACTIVE":"INACTIVE");
    LogMessage("    Log Flushed Streams: %s\n",
               s4data.log_flushed_streams ? "ACTIVE":"INACTIVE");
    LogMessage("    MinTTL: %d\n", s4data.min_ttl);
    LogMessage("    TTL Limit: %d\n", s4data.ttl_limit);
    LogMessage("    Async Link: %d\n", s4data.asynchronous_link);
    LogMessage("    State Protection: %d\n", s4data.state_protection);
    LogMessage("    Self preservation threshold: %d\n", s4data.sp_threshold);
    LogMessage("    Self preservation period: %d\n", s4data.sp_period);
    LogMessage("    Suspend threshold: %d\n", s4data.suspend_threshold);
    LogMessage("    Suspend period: %d\n", s4data.suspend_period);
    LogMessage("    Enforce TCP State: %s\n",
            s4data.enforce_state ? "ACTIVE" : "INACTIVE");
    LogMessage("    Midstream Drop Alerts: %s\n\n",
            s4data.ms_inline_alerts ? "ACTIVE" : "INACTIVE");

}


/*
 * Function: ParseStream4Args(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
void ParseStream4Args(char *args)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;

    s4data.timeout = PRUNE_QUANTA;
    s4data.memcap = STREAM4_MEMORY_CAP;
    s4data.stateful_inspection_flag = 1;
    s4data.state_alerts = 0;
    s4data.evasion_alerts = 1;
    s4data.ps_alerts = 0;
    s4data.reassemble_client = s4data.reassemble_server = 0;
    s4data.log_flushed_streams = 0;
    s4data.min_ttl = 1;
    s4data.path_mtu = 1460;
    s4data.ttl_limit = STREAM4_TTL_LIMIT;
    s4data.asynchronous_link = 0;
    s4data.flush_data_diff_size = 500; 
    s4data.zero_flushed_packets = 0;
    
    /* if no arguments, go ahead and return */
    if(args == NULL || args[0] == '\0')
    {
        if(!pv.quiet_flag) {
            DisplayStream4Config();
        }
        return;
    }

    i=0;

    toks = mSplit(args, ",", 12, &num_toks, 0);
    
    while(i < num_toks)
    {
        index = toks[i];

        while(isspace((int)*index)) index++;

        stoks = mSplit(index, " ", 4, &s_toks, 0);

        if(!strcasecmp(stoks[0], "noinspect"))
        {
            s4data.stateful_inspection_flag = 0;
        }
        else if(!strcasecmp(stoks[0], "asynchronous_link"))
        {
            s4data.asynchronous_link = 1;
        }
        else if(!strcasecmp(stoks[0], "keepstats"))
        {
            s4data.track_stats_flag = STATS_HUMAN_READABLE;

            if(s_toks > 1)
            {
                if(!strcasecmp(stoks[1], "machine"))
                {
                    s4data.track_stats_flag = STATS_MACHINE_READABLE;
                }
                else if(!strcasecmp(stoks[1], "binary"))
                {
                    s4data.track_stats_flag = STATS_BINARY;
                    stats_log = (StatsLog *) calloc(sizeof(StatsLog), 
                                                    sizeof(char));
                    stats_log->filename = strdup("snort-unified.stats");
                    OpenStatsFile();
                } 
                else
                {
                    ErrorMessage("Bad stats mode for stream4, ignoring\n");
                    s4data.track_stats_flag = 0;
                }
            }
        }
        else if(!strcasecmp(stoks[0], "detect_scans"))
        {
            s4data.ps_alerts = 1;
        }
        else if(!strcasecmp(stoks[0], "log_flushed_streams"))
        {
            s4data.log_flushed_streams = 1;
        }
        else if(!strcasecmp(stoks[0], "detect_state_problems"))
        {
            s4data.state_alerts = 1;
        }
        else if(!strcasecmp(stoks[0], "disable_evasion_alerts"))
        {
            s4data.evasion_alerts = 0;
        }
        else if(!strcasecmp(stoks[0], "timeout"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.timeout = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad timeout in config file, "
                           "defaulting to %d seconds\n", file_name, file_line, 
                           PRUNE_QUANTA);

                s4data.timeout = PRUNE_QUANTA;
            }
        }
        else if(!strcasecmp(stoks[0], "memcap"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.memcap = atoi(stoks[1]);

                if(s4data.memcap < 16384)
                {
                    LogMessage("WARNING %s(%d) => Ludicrous (<16k) memcap "
                               "size, setting to default (%d bytes)\n", file_name, 
                               file_line, STREAM4_MEMORY_CAP);
                    
                    s4data.memcap = STREAM4_MEMORY_CAP;
                }
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad memcap in config file, "
                           "defaulting to %d bytes\n", file_name, file_line, 
                           STREAM4_MEMORY_CAP);

                s4data.memcap = STREAM4_MEMORY_CAP;
            }
        }
        else if(!strcasecmp(stoks[0], "ttl_limit"))
        {
            if(s_toks > 1)
            {
                if(stoks[1] == NULL || stoks[1][0] == '\0')
                {
                    FatalError("%s(%d) => ttl_limit requires an integer argument\n",
                            file_name,file_line);
                }
            
                if(isdigit((int)stoks[1][0]))
                {
                    s4data.ttl_limit = atoi(stoks[1]);
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad TTL Limit"
                               "size, setting to default (%d\n", file_name, 
                               file_line, STREAM4_TTL_LIMIT);

                    s4data.ttl_limit = STREAM4_TTL_LIMIT;
                }
            }
            else
            {
                FatalError("%s(%d) => ttl_limit requires an integer argument\n",
                        file_name,file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "self_preservation_threshold"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.sp_threshold = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad sp_threshold in config file, "
                           "defaulting to %d new sessions/second\n", file_name, 
                           file_line, SELF_PRES_THRESHOLD);

                s4data.sp_threshold = SELF_PRES_THRESHOLD;
            }
        }
        else if(!strcasecmp(stoks[0], "self_preservation_period"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.sp_period = atoi(stoks[1]);
            }
            else            {
                LogMessage("WARNING %s(%d) => Bad sp_period in config file, "
                           "defaulting to %d seconds\n", file_name, file_line, 
                           SELF_PRES_PERIOD);

                s4data.sp_period = SELF_PRES_PERIOD;
            }
        }
        else if(!strcasecmp(stoks[0], "suspend_threshold"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.suspend_threshold = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad suspend_threshold in config "
                        "file, defaulting to %d new sessions/second\n", 
                        file_name, file_line, SUSPEND_THRESHOLD);

                s4data.suspend_threshold = SUSPEND_THRESHOLD;
            }
        }
        else if(!strcasecmp(stoks[0], "suspend_period"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.suspend_period = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad suspend_period in config file, "
                           "defaulting to %d seconds\n", file_name, file_line, 
                           SUSPEND_PERIOD);

                s4data.suspend_period = SUSPEND_PERIOD;
            }
        }
        else if(!strcasecmp(stoks[0], "enforce_state"))
        {
            s4data.enforce_state = 1;
        }
        else if(!strcasecmp(stoks[0], "midstream_drop_alerts"))
        {
            s4data.ms_inline_alerts = 1;
        }
        else if(!strcasecmp(stoks[0], "state_protection"))
        {
            s4data.state_protection = 1;
        } else {
            LogMessage("WARNING %s(%d) => Unknown stream4: option: %s\n",
                       file_name, file_line, stoks[0]);
        }

        mSplitFree(&stoks, s_toks);

        i++;
    }

    mSplitFree(&toks, num_toks);

    if(!pv.quiet_flag)
    {
        DisplayStream4Config();
    }
}


void Stream4InitReassembler(u_char *args)
{
    char **toks;
    int num_toks;
    int i;
    int j = 0;
    char *index;

    if(s4data.stream4_active == 0)
    {
        FatalError("Please activate stream4 before trying to "
                   "activate stream4_reassemble\n");
    }

    s4data.reassembly_alerts = 1;
    s4data.reassemble_client = 1; 
    s4data.reassemble_server = 0;
    s4data.assemble_ports[21] = 1;
    s4data.assemble_ports[23] = 1;
    s4data.assemble_ports[25] = 1;
    s4data.assemble_ports[53] = 1;
    s4data.assemble_ports[80] = 1;
    s4data.assemble_ports[143] = 1;
    s4data.assemble_ports[110] = 1;
    s4data.assemble_ports[111] = 1;
    s4data.assemble_ports[513] = 1;
    s4data.assemble_ports[1433] = 1;
    s4data.reassy_method = METHOD_FAVOR_OLD;

    /* setup for self preservaton... */
    s4data.emergency_ports[21] = 1;
    s4data.emergency_ports[23] = 1;
    s4data.emergency_ports[25] = 1;
    s4data.emergency_ports[53] = 1;
    s4data.emergency_ports[80] = 1;
    s4data.emergency_ports[143] = 1;
    s4data.emergency_ports[110] = 1;
    s4data.emergency_ports[111] = 1;
    s4data.emergency_ports[513] = 1;
    s4data.emergency_ports[1433] = 1;
    
    if(args == NULL)
    {
        s4data.reassemble_server = 0;

        if(!pv.quiet_flag)
        {
            char buf[STD_BUF+1];
            LogMessage("Stream4_reassemble config:\n");
            LogMessage("    Server reassembly: %s\n", 
                    s4data.reassemble_server ? "ACTIVE": "INACTIVE");
            LogMessage("    Client reassembly: %s\n", 
                    s4data.reassemble_client ? "ACTIVE": "INACTIVE");
            LogMessage("    Reassembler alerts: %s\n", 
                       s4data.reassembly_alerts ? "ACTIVE": "INACTIVE");
            LogMessage("    Zero out flushed packets: %s\n", 
                       s4data.zero_flushed_packets ? "ACTIVE": "INACTIVE");
            LogMessage("    flush_data_diff_size: %d\n", 
                       s4data.flush_data_diff_size);

            memset(buf, 0, STD_BUF+1);
            snprintf(buf, STD_BUF, "    Ports: "); 

            for(i=0;i<65536;i++)
            {
                if(s4data.assemble_ports[i])
                {
                    sfsnprintfappend(buf, STD_BUF, "%d ", i);
                    j++;
                }

                if(j > 20)
                { 
                    LogMessage("%s...\n", buf);
                    return;
                }
            }

            LogMessage("%s\n", buf);
            memset(buf, 0, STD_BUF+1);
            snprintf(buf, STD_BUF, "    Emergency Ports: ");
            j=0;

            for(i=0;i<65536;i++)
            {
                if(s4data.emergency_ports[i])
                {
                    sfsnprintfappend(buf, STD_BUF, "%d ", i);
                    j++;
                }

                if(j > 20)
                { 
                    LogMessage("%s...\n", buf);
                    return;
                }
            }

            LogMessage("%s\n", buf);
        }
        return;
    }
    else
    {
    }

    toks = mSplit(args, ",", 12, &num_toks, 0);

    i=0;

    while(i < num_toks)
    {
        index = toks[i];
        while(isspace((int)*index)) index++;

        if(!strncasecmp(index, "clientonly", 10))
        {
            s4data.reassemble_client = 1;
            s4data.reassemble_server = 0;
        }
        else if(!strncasecmp(index, "serveronly", 10))
        {
            s4data.reassemble_server = 1;
            s4data.reassemble_client = 0;
        }
        else if(!strncasecmp(index, "both", 4))
        {
            s4data.reassemble_client = 1;
            s4data.reassemble_server = 1;
        }
        else if(!strncasecmp(index, "noalerts", 8))
        {
            s4data.reassembly_alerts = 0;
        }
        else if(!strncasecmp(index, "favor_old", 9))
        {
            s4data.reassy_method = METHOD_FAVOR_OLD;
        }
        else if(!strncasecmp(index, "favor_new", 9))
        {
            s4data.reassy_method = METHOD_FAVOR_NEW;
        }
        else if(!strncasecmp(index, "ports", 5))
        {
            char **ports;
            int num_ports;
            char *port;
            int j = 0;
            u_int32_t portnum;

            for(j = 0;j<65535;j++)
            {
                s4data.assemble_ports[j] = 0;
            }

            ports = mSplit(index, " ", 40, &num_ports, 0);

            j = 1;

            while(j < num_ports)
            {
                port = ports[j];

                if(isdigit((int)port[0]))
                {
                    portnum = atoi(port);

                    if(portnum > 65535)
                    {
                        FatalError("%s(%d) => Bad port list to "
                                   "reassembler\n", file_name, file_line);
                    }

                    s4data.assemble_ports[portnum] = 1;
                }
                else if(!strncasecmp(port, "all", 3))
                {
                    memset(&s4data.assemble_ports, 1, 65536);
                }
                else if(!strncasecmp(port, "default", 7))
                {
                    s4data.assemble_ports[21] = 1;
                    s4data.assemble_ports[23] = 1;
                    s4data.assemble_ports[25] = 1;
                    s4data.assemble_ports[53] = 1;
                    s4data.assemble_ports[80] = 1;
                    s4data.assemble_ports[143] = 1;
                    s4data.assemble_ports[110] = 1;
                    s4data.assemble_ports[111] = 1;
                    s4data.assemble_ports[513] = 1;
                    s4data.assemble_ports[1433] = 1;
                }

                j++;
            }

            mSplitFree(&ports, num_ports);
        }
        else if(!strncasecmp(index, "emergency_ports", 15))
        {
            char **ports;
            int num_ports;
            char *port;
            int j = 0;
            u_int32_t portnum;

            for(j = 0;j<65535;j++)
            {
                s4data.emergency_ports[j] = 0;
            }

            ports = mSplit(args, " ", 40, &num_ports, 0);

            j = 0;

            while(j < num_ports)
            {
                port = ports[j];

                if(isdigit((int)port[0]))
                {
                    portnum = atoi(port);

                    if(portnum > 65535)
                    {
                        FatalError("%s(%d) => Bad port list to "
                                   "reassembler\n", file_name, file_line);
                    }

                    s4data.emergency_ports[portnum] = 1;
                }
                else if(!strncasecmp(port, "all", 3))
                {
                    memset(&s4data.emergency_ports, 1, 65536);
                }
                else if(!strncasecmp(port, "default", 7))
                {
                    s4data.emergency_ports[21] = 1;
                    s4data.emergency_ports[23] = 1;
                    s4data.emergency_ports[25] = 1;
                    s4data.emergency_ports[53] = 1;
                    s4data.emergency_ports[80] = 1;
                    s4data.emergency_ports[143] = 1;
                    s4data.emergency_ports[110] = 1;
                    s4data.emergency_ports[111] = 1;
                    s4data.emergency_ports[513] = 1;
                    s4data.emergency_ports[1433] = 1;
                }

                j++;
            }

            mSplitFree(&ports, num_ports);
        }
        else if(!strcasecmp(index, "zero_flushed_packets"))
        {
            s4data.zero_flushed_packets = 1;
        }
        else if(!strncasecmp(index, "flush_data_diff_size", 
                    strlen("flush_data_diff_size")))
        {
            /* using strncasecmp since it will be flush_data_diff_size <int> */
            char *number_str;
            number_str = strrchr(index,' '); /* find the last ' ' */

            if(number_str && *number_str != '\0')
            {
                number_str++; 
            }

            if(number_str && *number_str != '\0' && (isdigit((int)*number_str)))
            {
                s4data.flush_data_diff_size = atoi(number_str);
                
                if(s4data.flush_data_diff_size < 0)
                {
                    FatalError("%s(%d) => Bad flush_data_diff_size in "
                            "config file\n", file_name, file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => Bad flush_data_diff_size in config file\n",
                           file_name, file_line);
            }
        }
        else
        {
            FatalError("%s(%d) => Bad stream4_reassemble option "
                       "specified: \"%s\"\n", file_name, file_line, toks[i]);
        }

        i++;
    }

    mSplitFree(&toks, num_toks);

    if(!pv.quiet_flag)
    {
        char buf[STD_BUF+1];
        LogMessage("Stream4_reassemble config:\n");
        LogMessage("    Server reassembly: %s\n", 
                   s4data.reassemble_server ? "ACTIVE": "INACTIVE");
        LogMessage("    Client reassembly: %s\n", 
                   s4data.reassemble_client ? "ACTIVE": "INACTIVE");
        LogMessage("    Reassembler alerts: %s\n", 
                   s4data.reassembly_alerts ? "ACTIVE": "INACTIVE");
        LogMessage("    Zero out flushed packets: %s\n", 
                   s4data.zero_flushed_packets ? "ACTIVE": "INACTIVE");
        LogMessage("    flush_data_diff_size: %d\n", 
                   s4data.flush_data_diff_size);

        memset(buf, 0, STD_BUF+1);
        snprintf(buf, STD_BUF, "    Ports: ");       

        for(i=0;i<65536;i++)
        {
            if(s4data.assemble_ports[i])
            {
                sfsnprintfappend(buf, STD_BUF, "%d ", i);
                j++;
            }

            if(j > 20)
            { 
                LogMessage("%s...\n", buf);
                return;
            }
        }

        LogMessage("%s\n", buf);
        memset(buf, 0, STD_BUF+1);
        snprintf(buf, STD_BUF, "    Emergency Ports: "); 
        j=0;

        for(i=0;i<65536;i++)
        {
            if(s4data.emergency_ports[i])
            {
                sfsnprintfappend(buf, STD_BUF, "%d ", i);
                j++;
            }

            if(j > 20)
            { 
                LogMessage("%s...\n", buf);
                return;
            }
        }

        LogMessage("%s\n", buf);
    }
}

/** 
 * Set that this side of the session has sent a fin.
 *
 * This overloads the next_seq variable to also be used to tell how
 * far forward we can acknowledge data.
 * 
 * @param p packet to grab the session from
 * @param s stream to set the next_seq on 
 * 
 * @return 0 if everything went ok
 */
static INLINE int SetFinSent(Packet *p, Session *ssn, int direction)
{
    Stream *stream;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "SetFinSet() called for %s\n",
                            direction ? "FROM_CLIENT":"FROM_SERVER"););

    if(direction == FROM_SERVER)
    {
        stream = &ssn->server;
        ssn->session_flags |= SSNFLAG_SERVER_FIN;
    }
    else
    {
        stream = &ssn->client;
        ssn->session_flags |= SSNFLAG_CLIENT_FIN;
    }
    
    stream->next_seq = ntohl(p->tcph->th_seq);

    return 0;
}

/** 
 * See if we can get ignore this packet
 *
 * The Emergency Status stuff is taken care of here.
 * 
 * @param p Packet
 * 
 * @return 1 if this packet isn't destined to be processeed, 0 otherwise
 */
static INLINE int NotForStream4(Packet *p)
{
    if(!(p->preprocessors & PP_STREAM4))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "p->preprocessors does not have STREAM4\n"););
        return 1;
    }

    if(p->tcph == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "p->tcph is null, returning\n"););
        return 1;
    }
    
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "REBUILT_STREAM returning\n"););
        return 1;
    }

    if(s4_emergency.status != OPS_NORMAL)
    {
        /* Check to see if we should return to our non-emergency mode.
         * If we happen to stay in SUSPSEND mode, exit out
         */

        if(p->pkth->ts.tv_sec >= s4_emergency.end_time)
        {
            s4_emergency.status = OPS_NORMAL;
            s4_emergency.end_time = 0;
            s4_emergency.new_session_count = 0;
            s4data.reassembly_alerts = s4_emergency.old_reassembly_alerts;
            s4data.reassemble_client = s4_emergency.old_reassemble_client; 
            s4data.reassemble_server = s4_emergency.old_reassemble_server;
            pv.assurance_mode = s4_emergency.old_assurance_mode;
            pv.stateful = s4_emergency.old_stateful_mode;
        }

        if(s4_emergency.status == OPS_SUSPEND)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "OPS_SUSPEND returning\n"););
            return 1;
        }
    }
    
    /* don't accept packets w/ bad checksums */
    if(p->csum_flags & CSE_IP || p->csum_flags & CSE_TCP)
    {
        DEBUG_WRAP(
                   u_int8_t c1 = (p->csum_flags & CSE_IP);
                   u_int8_t c2 = (p->csum_flags & CSE_TCP);
                   DebugMessage(DEBUG_STREAM, "IP CHKSUM: %d, CSE_TCP: %d",
                                c1,c2);
                   DebugMessage(DEBUG_STREAM, "Bad checksum returning\n");
                   );
        
        p->packet_flags |= PKT_STREAM_UNEST_UNI;
        return 1;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Packet is for stream4...\n"););
    return 0;
}


/** 
 * Subtract from the byte counters for the stream session
 * 
 * @param stream Stream to adjust the byte counters on
 * @param sub amount to subtract from the byte_counters
 */
static INLINE void StreamSegmentSub(Stream *stream, u_int16_t sub)
{
    /* don't allow us to overflow */
#ifdef _DEBUG_SEGMENTS
    DebugMessage(DEBUG_STREAM, "[sss] %u -> %u (mem: %u)\n,",
            stream->bytes_tracked,
            stream->bytes_tracked - sub,
            stream4_memory_usage);
#endif /* DEBUG_SEGMENTS */

    if((stream->bytes_tracked - sub) > stream->bytes_tracked)
    {
        stream->bytes_tracked = 0;
    }
    else
    {
        stream->bytes_tracked -= sub;
    }

}


/** 
 * Add to the byte counters for the stream session
 * 
 * @param stream Stream to adjust the byte counters on
 * @param add amount to add to the byte_counters
 */
static INLINE void StreamSegmentAdd(Stream *stream, u_int16_t add)
{
    /* don't allow us to overflow */
#ifdef _DEBUG_SEGMENTS
    DebugMessage(DEBUG_STREAM, "[ssa] %u -> %u (mem: %u)\n,",
            stream->bytes_tracked,
            stream->bytes_tracked + add,
            stream4_memory_usage);
#endif /* _DEBUG_SEGMENTS */

    /* don't allow us to overflow */
    if((stream->bytes_tracked + add) < stream->bytes_tracked)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"[E] How'd we get this high?\n"););
        return;
    }
    else
    {
        stream->bytes_tracked += add;
        stream->bytes_sent += add;
        stream->pkts_sent++;
    }

}



/** 
 * Make sure that we do not log
 * 
 * @param p Packet to evaluate
 * @param stream Stream to compare against
 * 
 * @return 1 if we are within established limits, 0 otherwise.
 */
static INLINE int WithinSessionLimits(Packet *p, Stream *stream)
{
    u_int32_t limit; 

    return 1;
    /* use a different limit if the session was picked up midstream
     * rather than having a full 3whs */

    if(((Session *)(p->ssnptr))->session_flags & SSNFLAG_MIDSTREAM)
    {
        limit = 5000;
    }
    else
    {
        limit = (MAX_STREAM_SIZE + 5000);
    }

    if((stream->bytes_tracked + p->dsize) >= limit)
    {
        /* Go ahead and remove these statistics since we're not going to
         * store the packet
         */
        StreamSegmentSub(stream, p->dsize);
        return 0;
    }

    return 1;
}


/**
 * Prune The state machine if we need to
 *
 * Also updates all variables related to pruning that only have to
 * happen at initialization
 *
 * For want of packet time at plugin initialization. (It only happens once.)
 * It wood be nice to get the first packet and do a little extra before
 * getting into the main snort processing loop.
 *   -- cpw
 * 
 * @param p Packet ptr
 */
static INLINE void PruneCheck(Packet *p)
{

    if (!s4data.last_prune_time)
    {
        s4data.last_prune_time = p->pkth->ts.tv_sec;
        return;
    }

    if( (u_int)(p->pkth->ts.tv_sec) > s4data.last_prune_time + s4data.timeout)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Prune time quanta exceeded, pruning "
                    "stream cache\n"););

        sfPerf.sfBase.iStreamTimeouts++;

        PruneSessionCache(p->pkth->ts.tv_sec, 0, NULL);
        s4data.last_prune_time = p->pkth->ts.tv_sec;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Pruned for timeouts, %lu sessions "
                    "active, %lu bytes " "in use\n", 
                    (unsigned long int) ubi_trCount(RootPtr), stream4_memory_usage);
                DebugMessage(DEBUG_STREAM, "Stream4 memory cap hit %lu times\n", 
                    safe_alloc_faults););
    }

}


/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 */
void ReassembleStream4(Packet *p)
{
    Session *ssn;
    int action;
    int reassemble = 0;
    u_int32_t pkt_seq;
    u_int32_t pkt_ack;
    int direction;
    static int alert_once_emerg   = 0;
    static int alert_once_suspend = 0;
#ifdef DEBUG
    static int pcount = 0;
    char flagbuf[9];

    pcount++;

    DebugMessage(DEBUG_STREAM, "pcount stream packet %d\n",pcount);
#endif

    if(NotForStream4(p))
        return;

    pc.tcp_stream_pkts++;

    reassemble = CheckPorts(p->sp, p->dp);

    /* if we're not doing stateful inspection... */
    if(s4data.stateful_inspection_flag == 0 && !reassemble)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "No stateful inspection on this port, returning"););
        return;
    }

    DEBUG_WRAP(
            CreateTCPFlagString(p, flagbuf);
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE), 
                "Got Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X\n",
                p->iph->ip_src.s_addr,
                p->sp,
                p->iph->ip_dst.s_addr,
                p->dp,
                flagbuf,
                ntohl(p->tcph->th_seq), ntohl(p->tcph->th_ack));
            );

    pkt_seq = ntohl(p->tcph->th_seq);
    pkt_ack = ntohl(p->tcph->th_ack);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"pkt_seq: %u, pkt_ack: %u\n", 
                pkt_seq, pkt_ack););

    /* see if we have a stream for this packet */
    ssn = GetSession(p);
    
    /*
    **  Let's leave this out for now until we figure out if we're going
    **  to make the rule language handle this type of policy (a.k.a
    **  not_established).
    */
    if(!ssn && s4data.enforce_state)
    {
        /*
        **  We treat IDS and IPS mode differently, because in IDS mode
        **  we are just monitoring so we pick up all legitimate traffic
        **  connections, which in this case (thanks to linux) is any
        **  flag combination (except RST) is valid as an initiator as
        **  long as the SYN flag is included.
        **
        **  In InlineMode, we WILL enforce the correct flag combinations
        **  or else we'll drop it.
        */
        if(!InlineMode())
        {
            if((p->tcph->th_flags & (TH_SYN|TH_RST)) != TH_SYN)
            {
                do_detect = 0;
                p->preprocessors = 0;

                return;
            }
        }
        else
        {
            /*
            **  We're in inline mode
            */
            if((p->tcph->th_flags & (TH_SYN|TH_ACK|TH_PUSH|TH_FIN|TH_RST)) 
                    != TH_SYN)
            {
                do_detect = 0;
                p->preprocessors = 0;

                InlineDrop();
            
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "Lets drop this its not a synner\n"););

                return;
            }
        }
    }

    if(ssn == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Calling CreateNewSession()\n"););

        p->packet_flags |= PKT_FROM_CLIENT;

        /*
         * If we are in "emergency mode", we become much more picky
         * about what we will accept as a session initiator.  Since
         * our goal is to regain 0 packet loss, we move to only accept
         * new sessions that begin with a SYN flag.  Note that we do
         * ignore the reserved bits on a session initiator as required
         * by ECN. --cmg
         */
        if((s4_emergency.status == OPS_NORMAL) ||
                ((p->tcph->th_flags & TH_NORESERVED) == TH_SYN))
        {
            ssn = CreateNewSession(p, pkt_seq, pkt_ack);

            if(ssn != NULL && ((p->tcph->th_flags & TH_NORESERVED) != TH_SYN))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Picking up session midstream\n"););

                ssn->session_flags |= SSNFLAG_MIDSTREAM;
            }


            /* 
             * keep track of how many sessions per second we're creating 
             * vs. the number of data packets per second we get on 
             * those sessions
             */
            if(s4data.state_protection)
                ++s4_emergency.new_session_count;

            /* perfstats */
            if(ssn != NULL)
            {
                AddStreamSession(&sfPerf.sfBase);
            }
        } 
        else 
        {
            ssn = NULL;
        }

        if(s4data.state_protection)
        {
            if(s4_emergency.new_session_count >= s4data.suspend_threshold)
            {
                s4_emergency.status = OPS_SUSPEND;
                s4_emergency.end_time = p->pkth->ts.tv_sec + s4data.suspend_period;            
                pv.assurance_mode = ASSURE_ALL;
                pv.stateful = 0;

                if(alert_once_suspend == 0)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4,
                            STREAM4_SUSPEND,
                            1,
                            0,
                            3,
                            STREAM4_SUSPEND_STR,
                            0);

                    alert_once_suspend = 1;
                }
            }
            else if(s4_emergency.new_session_count >= s4data.sp_threshold)
            {
                s4_emergency.status = OPS_SELF_PRESERVATION;
                s4_emergency.end_time = p->pkth->ts.tv_sec + s4data.sp_period;
                s4_emergency.old_reassembly_alerts = s4data.reassembly_alerts;
                s4_emergency.old_reassemble_client = s4data.reassemble_client; 
                s4_emergency.old_reassemble_server = s4data.reassemble_server;
                s4_emergency.old_assurance_mode = pv.assurance_mode;
                s4_emergency.old_stateful_mode = pv.stateful;

                if(alert_once_emerg == 0)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4,
                            STREAM4_EMERGENCY,
                            1,
                            0,
                            3,
                            STREAM4_EMERGENCY_STR,
                            0);
                    
                    alert_once_emerg = 1;
                }
            }
        }

        p->packet_flags = PKT_STREAM_UNEST_UNI;

        if(ssn == NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"NULL SSN, maybe in emergency in "
                        "CreateNewSession, returning\n"););

            /*
             * Mark that this packet isn't worth doing IDS on.  This
             * is self preservation because either our system is under
             * session trashing attacks.  This will be the case under
             * super rapid tools like tcpisc that are generating
             * bogus TCP datagrams all the time  
             */
            if(s4_emergency.status != OPS_NORMAL)
            {
                DisableDetect(p);
            }

            return;
        }           
    }    
    else
    {
        if(p->dsize != 0 && s4_emergency.status == OPS_NORMAL)
            s4_emergency.new_session_count = 0;
    }


    p->ssnptr = ssn;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "[i] Tracked Bytes: (client: %d, server: %d)\n",
                ssn->client.bytes_tracked,
                ssn->server.bytes_tracked););

    /* update the stream window size */
    if((direction = GetDirection(ssn, p)) == SERVER_PACKET)
    {
        p->packet_flags |= PKT_FROM_SERVER;
        ssn->client.win_size = ntohs(p->tcph->th_win);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "server packet: %s\n", flagbuf););
    }
    else
    {
        p->packet_flags |= PKT_FROM_CLIENT;
        ssn->server.win_size = ntohs(p->tcph->th_win);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "client packet: %s\n", flagbuf););
    }

    /* update the time for this session */
    ssn->last_session_time = p->pkth->ts.tv_sec;

    /* go into the FSM to maintain stream state for this packet */    
    if(s4data.asynchronous_link)
    {
        action = UpdateStateAsync(ssn, p, pkt_seq);
    }
    else
    {
        action = UpdateState2(ssn, p, pkt_seq);
    }

    /* if this packet has data, maybe we should store it */
    if(p->dsize && reassemble)
    {
        StoreStreamPkt(ssn, p, pkt_seq);
    }
    else
    {
        /* Since we're not storing the packet on this session, let's
         * decrement the bytes tracked */
        if(direction == SERVER_PACKET)
            StreamSegmentSub(&ssn->server, p->dsize);        
        else
            StreamSegmentSub(&ssn->client, p->dsize);
    }


    /* 
     * resolve actions to be taken as indicated by state transitions or
     * normal traffic
     */
    if(s4data.asynchronous_link)
    {
        TcpActionAsync(ssn, p, action, direction, pkt_seq, pkt_ack);
    }
    else
    {
        TcpAction(ssn, p, action, direction, pkt_seq, pkt_ack);
    }   

    /*
     * Kludge:  Sometime's we can drop a bad session
     *
     * Only try and mark the stream as established if we still have a
     * valid session AFTER the stream is done
     *
     * p->ssnptr == NULL when the action indicates we should have
     * dropped the session
     */
    if(p->ssnptr == ssn)  /* this is not true when the session is dropped */
    {
        /* mark this packet is part of an established stream if possible */
        if(((s4data.asynchronous_link == 0) &&
           (((ssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
              == (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) && 
           (ssn->server.state >= ESTABLISHED) && 
           (ssn->client.state >= ESTABLISHED))) ||
           ((s4data.asynchronous_link == 1) &&
           ((((ssn->session_flags & SSNFLAG_SEEN_CLIENT)) &&
           (ssn->client.state >= ESTABLISHED)) ||
           (((ssn->session_flags & SSNFLAG_SEEN_SERVER)) &&
           (ssn->server.state >= ESTABLISHED)))))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Stream is established!,ssnflags = 0x%x\n",
                        ssn->session_flags););

            ssn->session_flags |= SSNFLAG_ESTABLISHED;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Stream is not established!\n"););

            if((ssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
                    == (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) 
            {
                /*
                 * we've seen packets in this stream from both the client and 
                 * the server, but we haven't gotten through the three way
                 * handshake
                 */
                p->packet_flags |= PKT_STREAM_UNEST_BI;
            }
            else
            {
                /* 
                 * this is the first time we've seen a packet 
                 * from this stream
                 */
                p->packet_flags |= PKT_STREAM_UNEST_UNI;
            }
        }

        if(ssn->session_flags  & SSNFLAG_ESTABLISHED)
        {
            /* we know this stream is established, lets skip the other checks
             * otherwise we get into clobbering our flags in the check below
             */
            p->packet_flags |= PKT_STREAM_EST;

            if(p->packet_flags & PKT_STREAM_UNEST_UNI)
            {
                p->packet_flags ^= PKT_STREAM_UNEST_UNI;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Marking stream as established\n"););
#ifdef DEBUG
            if(p->packet_flags & PKT_FROM_CLIENT)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "pkt is from client\n"););
            } 

            if(p->packet_flags & PKT_FROM_SERVER)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "pkt is from server\n"););
            } 
#endif /*DEBUG*/
        }
    }


    PrintSessionCache();

    /* see if we need to prune the session cache */
    PruneCheck(p);

    return;
}



/**
 * Queues a state transition for UpdateState2
 * 
 * @param transition the state to transition to
 * @param sptr pointer to the stream to queue the transition for
 * @param expected_flags flag we need to see to accept the transition
 * @param seq_num sequence number of the packet initiating the transition
 * @param chk_seq flag to indicate if the seq number actually needs to be
 * checked
 *
 * @return void function
 */
void INLINE QueueState(u_int8_t transition, Stream *sptr, 
        u_int8_t expected_flags, u_int32_t seq_num, u_int8_t chk_seq)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "[^^] Queing transition to %s, flag 0x%X, seq: 0x%X\n", 
                state_names[transition], expected_flags, seq_num););

    sptr->state_queue = transition;
    sptr->expected_flags = expected_flags;
    sptr->stq_chk_seq = chk_seq;
    sptr->trans_seq = seq_num;
    return;
}

/**
 * Evaluate queued state transitions for completion criteria
 *
 * @param sptr pointer to the stream to be evaluated
 * @param flags flags of the current packet
 * @param ack ack number of the current packet
 *
 * @returns 1 on successful state transition, 0 on no transition
 */
int INLINE EvalStateQueue(Stream *sptr, u_int8_t flags, u_int32_t ack)
{
    if(sptr->expected_flags != 0)
    {
        if((flags & sptr->expected_flags) != 0)
        {
            if(sptr->stq_chk_seq && (SEQ_GEQ(ack, sptr->trans_seq)))
            {

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[^^] Accepting %s state transition\n", 
                            state_names[sptr->state_queue]););
                sptr->state = sptr->state_queue;
                sptr->expected_flags = 0;
                sptr->trans_seq = 0;
                return 1;
            }
            else if(!sptr->stq_chk_seq)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[^^] Accepting %s state transition\n", 
                            state_names[sptr->state_queue]););
                sptr->state = sptr->state_queue;
                sptr->expected_flags = 0;
                sptr->trans_seq = 0;
                return 1;

            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "[!!] sptr->stq_chk_seq: %d  "
                            "[ack: 0x%X expected: 0x%X]\n", sptr->stq_chk_seq, 
                            ack, sptr->trans_seq););
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "[!!] flags: 0x%X  expected: 0x%X, bitwise: 0x%X\n", 
                        flags, sptr->expected_flags, 
                        (flags&sptr->expected_flags)););
        }
    }

    return 0;
}



int UpdateState2(Session *ssn, Packet *p, u_int32_t pkt_seq)
{
    int direction;
    int retcode = 0;
    Stream *talker = NULL;
    Stream *listener = NULL;
    DEBUG_WRAP(
            char *t = NULL;
            char *l = NULL;
            );

    direction = GetDirection(ssn, p);

    if(p->tcph->th_flags & TH_FIN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "Marking that a fin was was sent %s\n",
                    (direction ? "FROM_CLIENT" : "FROM_SERVER")););
        SetFinSent(p, ssn, direction);
    }

    if(direction == FROM_SERVER)
    {
        ssn->session_flags |= SSNFLAG_SEEN_SERVER;
        talker = &ssn->server;
        listener = &ssn->client;

        DEBUG_WRAP(
                t = strdup("Server");
                l = strdup("Client"););
    }
    else
    {
        ssn->session_flags |= SSNFLAG_SEEN_CLIENT;
        talker = &ssn->client;
        listener = &ssn->server;

        DEBUG_WRAP(
                t = strdup("Client");
                l = strdup("Server"););
    }

    EvalStateQueue(talker, p->tcph->th_flags, ntohl(p->tcph->th_ack));

    if(talker->state != ESTABLISHED)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s [talker] state: %s\n", t, state_names[talker->state]););
    }
    if(listener->state != ESTABLISHED)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s state: %s\n", l, state_names[listener->state]););
    }

    StreamSegmentAdd(talker, p->dsize); 

    if(talker->state == ESTABLISHED)
    {
        listener->win_size = ntohs(p->tcph->th_win);
    }

    if(p->tcph->th_flags & TH_RST)
    {
        /* check to make sure the RST is in window */
        if(CheckRst(ssn, direction, pkt_seq, p))
        {
            ssn->client.state = CLOSED;
            ssn->server.state = CLOSED;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                        "   Client Transition: CLOSED\n");
                    DebugMessage(DEBUG_STREAM_STATE,  
                        "   Server Transision: CLOSED\n");
                    if(l) free(l);
                    if(t) free(t););

            return ACTION_FLUSH_CLIENT_STREAM | 
                ACTION_FLUSH_SERVER_STREAM | 
                ACTION_DROP_SESSION;
        }
    }

    switch(listener->state)
    {
        case LISTEN:
            /* only valid packet for this state is a SYN...
             *  or SYN + ECN crap.
             *
             * Revised: As long as it's got a SYN and not a
             * RST, Lets try to make the session start.  It
             * may just timeout -- cmg
             */
            if((p->tcph->th_flags & TH_SYN) &&
                    !(p->tcph->th_flags & TH_RST))
            {
                QueueState(SYN_RCVD, listener, TH_SYN| TH_ACK, 0, NO_CHK_SEQ);

                if(talker->state != SYN_SENT)
                {
                    talker->state = SYN_SENT;
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: SYN_SENT\n", t););
                }
            }

            if(p->dsize != 0)
                retcode |= ACTION_DATA_ON_SYN;
            break;

        case SYN_SENT:
            if((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
            {
                if(talker->state != SYN_RCVD)
                {
                    talker->state = SYN_RCVD;

                    DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: SYN_RCVD\n", t););
                }

                QueueState(ESTABLISHED, listener, TH_ACK, pkt_seq, CHK_SEQ);

                /* ECN response */
                if((p->tcph->th_flags & TH_RES2) && 
                        ssn->session_flags & SSNFLAG_ECN_CLIENT_QUERY)
                {
                    ssn->session_flags |= SSNFLAG_ECN_SERVER_REPLY;
                }

                retcode |= ACTION_SET_SERVER_ISN;
            }                    

            break;

        case SYN_RCVD:
            if(p->tcph->th_flags & TH_ACK)
            {
                listener->state = ESTABLISHED;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: ESTABLISHED\n", l););
                retcode |= ACTION_COMPLETE_TWH;
            }

            break;

        case ESTABLISHED:
            if(p->tcph->th_flags & TH_ACK)
            {
                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }

            if((p->tcph->th_flags & TH_FIN) == TH_FIN)
            {
                talker->state = FIN_WAIT_1;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: FIN_WAIT_1\n", t););
                QueueState(CLOSE_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);
            }

            break;

        case CLOSE_WAIT:
            QueueState(LAST_ACK, talker, TH_FIN, pkt_seq, NO_CHK_SEQ);

            if(p->tcph->th_flags == TH_ACK)
            {
                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }

            break;

        case LAST_ACK:
            if(p->tcph->th_flags & TH_ACK)
            {
                listener->state = CLOSED;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: CLOSED\n", l););

                if(talker->state == TIME_WAIT)
                {
                    talker->state = CLOSED;
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: CLOSED\n", t););
                }

                retcode |= (ACTION_FLUSH_CLIENT_STREAM | 
                        ACTION_FLUSH_SERVER_STREAM | 
                        ACTION_DROP_SESSION);
            }

            break;

        case FIN_WAIT_1:
            if((p->tcph->th_flags & (TH_ACK|TH_FIN)) == (TH_ACK|TH_FIN))
            {
                talker->state = LAST_ACK;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: LAST_ACK\n", t););
                QueueState(TIME_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }
            else if(p->tcph->th_flags == TH_ACK)
            {
                QueueState(LAST_ACK, talker, TH_FIN, pkt_seq, NO_CHK_SEQ);
                listener->state = FIN_WAIT_2;
                DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: FIN_WAIT_2\n", l););

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }

            break;

        case FIN_WAIT_2:
            if(p->tcph->th_flags == (TH_FIN|TH_ACK))
            {
                talker->state = LAST_ACK;
                QueueState(TIME_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_FLUSH_CLIENT_STREAM | ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_FLUSH_SERVER_STREAM | ACTION_ACK_CLIENT_DATA;
            }
            else if(p->tcph->th_flags == TH_FIN)
            {
                talker->state = LAST_ACK;
                DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: LAST_ACK\n", t););

                QueueState(TIME_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_FLUSH_SERVER_STREAM;
                else
                    retcode |= ACTION_FLUSH_CLIENT_STREAM;
            }

            break;

        case TIME_WAIT:
        case CLOSED:    
            return ACTION_FLUSH_CLIENT_STREAM | ACTION_DROP_SESSION;    
    }

    DEBUG_WRAP(
            if(l) free(l);
            if(t) free(t););

    return retcode;
}


/* int UpdateStateAsync(Session *ssn, Packet *p, u_int32_t pkt_seq)
 * 
 * Purpose: Do the state transition table for packets based solely on
 * one-sided converstations
 *
 * Returns:  which ACTIONS need to be taken on this state
 */
 
int UpdateStateAsync(Session *ssn, Packet *p, u_int32_t pkt_seq)
{
    int direction;

    direction = GetDirection(ssn, p);

    switch(direction)
    {
        case FROM_SERVER:  /* packet came from the server */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                        "Client State: SYN_SENT\n"););

            StreamSegmentAdd(&ssn->server, p->dsize); 

            ssn->session_flags |= SSNFLAG_SEEN_SERVER;

            switch(ssn->server.state)
            {
                case SYN_RCVD:
                    /* This is the first state the reassembler can stick in
                       in the Asynchronus state */

                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                "Server state: SYN_RCVD\n"););
                    if((p->tcph->th_flags & TH_NORESERVED) == (TH_SYN|TH_ACK))
                    {
                        ssn->server.state = ESTABLISHED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Server Transition: ESTABLISHED\n"););
                        return ACTION_COMPLETE_TWH;
                    }
                    return ACTION_NOTHING;

                case ESTABLISHED:
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Server state: ESTABLISHED\n"););
                    if(p->tcph->th_flags & TH_FIN)
                    {
                        ssn->server.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: FIN_WAIT_1\n"););

                        return ACTION_FLUSH_SERVER_STREAM|ACTION_DROP_SESSION;
                    }
                    else if(p->tcph->th_flags & TH_RST)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                    "Got RST (0x%X)\n", 
                                    p->tcph->th_flags););
                        ssn->server.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Server Transition: CLOSED\n"););

                        return ACTION_FLUSH_SERVER_STREAM | ACTION_DROP_SESSION;
                    }

                    return ACTION_NOTHING;
            }

        case FROM_CLIENT:

            StreamSegmentAdd(&ssn->client, p->dsize);

            ssn->session_flags |= SSNFLAG_SEEN_CLIENT;

            switch(ssn->client.state)
            {
                case SYN_SENT:
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Client State: SYN_SENT\n"););
                    if(p->tcph->th_flags & TH_RST)
                    {
                        ssn->client.state = CLOSED;

                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: CLOSED -- RESET\n"););

                        return ACTION_FLUSH_CLIENT_STREAM | ACTION_DROP_SESSION;
                    }
                    else if(p->tcph->th_flags & TH_ACK)
                    {
                        ssn->client.state = ESTABLISHED;

                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: ESTABLISHED\n"););

                        return ACTION_NOTHING;
                    }


                    return ACTION_NOTHING;


                case ESTABLISHED:
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Client state: ESTABLISHED\n"););

                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Session State: ESTABLISHED\n"););
                    ssn->session_flags |= SSNFLAG_ESTABLISHED;


                    if(p->tcph->th_flags & TH_FIN)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                    "Got FIN (0x%X)\n", 
                                    p->tcph->th_flags););
                        ssn->client.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: CLOSEd\n"););

                        return ACTION_FLUSH_CLIENT_STREAM|ACTION_DROP_SESSION;
                    }
                    else if(p->tcph->th_flags & TH_RST)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                    "Got RST (0x%X)\n", 
                                    p->tcph->th_flags););
                        ssn->client.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: Closed\n"););

                        return ACTION_FLUSH_CLIENT_STREAM | ACTION_DROP_SESSION;
                    }
                    break;
            }
    }

    return ACTION_NOTHING;
}



Session *CreateNewSession(Packet *p, u_int32_t pkt_seq, u_int32_t pkt_ack)
{
    Session *idx = NULL;
    static u_int8_t savedfpi; /* current flush point index */
    u_int8_t fpi;            /* flush point index */


    /* assign a psuedo random flush point */
    savedfpi++;
    fpi = savedfpi % FCOUNT;    

    switch(p->tcph->th_flags)
    {
        case TH_RES1|TH_RES2|TH_SYN: /* possible ECN traffic */
            if(p->iph->ip_tos == 0x02)
            {
                /* it is ECN traffic */
                p->packet_flags |= PKT_ECN;
            }

            /* fall through */

        case TH_SYN:  /* setup session on first packet of TWH */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session)););

            idx = (Session *) SafeAlloc(sizeof(Session), p->pkth->ts.tv_sec,
                    NULL);

            if(s4data.reassemble_server)
                (void)ubi_trInitTree(&idx->server.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            if(s4data.reassemble_client)
                (void)ubi_trInitTree(&idx->client.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            idx->server.state = LISTEN;        
            idx->server.ip = p->iph->ip_dst.s_addr;
            idx->server.port = p->dp;

            idx->client.state = SYN_SENT;
            idx->client.ip = p->iph->ip_src.s_addr;
            idx->client.port = p->sp;
            idx->client.isn = pkt_seq;
            idx->server.win_size = ntohs(p->tcph->th_win);

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;

            idx->session_flags |= SSNFLAG_SEEN_CLIENT;

            if(p->packet_flags & PKT_ECN)
            {
                idx->session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
            }

            idx->flush_point = flush_points[fpi];
            break;

        case TH_RES2|TH_SYN|TH_ACK:
            if(p->iph->ip_tos == 0x02)
            {
                p->packet_flags |= PKT_ECN;
            }
            else
            {
                if(s4data.ps_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4,
                            STREAM4_STEALTH_ACTIVITY,
                            1,
                            0,
                            3,
                            STREAM4_STEALTH_ACTIVITY_STR,
                            0);

                    break;
                }

                return NULL;
            }

            /* fall through */

        case TH_SYN|TH_ACK: /* maybe we missed the SYN packet... */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session)););

            idx = (Session *) SafeAlloc(sizeof(Session), p->pkth->ts.tv_sec, 
                    NULL);

            if(s4data.reassemble_server)
                (void)ubi_trInitTree(&idx->server.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            if(s4data.reassemble_client)
                (void)ubi_trInitTree(&idx->client.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            idx->server.state = SYN_RCVD;
            idx->client.state = SYN_SENT;

            idx->server.ip = p->iph->ip_src.s_addr;
            idx->server.port = p->sp;
            idx->server.isn = pkt_seq;
            idx->client.win_size = ntohs(p->tcph->th_win);

            idx->client.ip = p->iph->ip_dst.s_addr;
            idx->client.port = p->dp;
            idx->client.isn = pkt_ack-1;

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;
            idx->session_flags = SSNFLAG_SEEN_SERVER;
            idx->flush_point = flush_points[fpi];
            break;

        case TH_ACK: 
        case TH_ACK|TH_PUSH: 
        case TH_FIN|TH_ACK:
        case TH_ACK|TH_URG:
        case TH_ACK|TH_PUSH|TH_URG:
        case TH_FIN|TH_ACK|TH_URG:
        case TH_ACK|TH_PUSH|TH_FIN:
        case TH_ACK|TH_PUSH|TH_FIN|TH_URG:
            /* 
             * missed the TWH or just got the last packet of the 
             * TWH, or we're catching this session in the middle
             */

            /* 
             * this traffic could also be bogus SmartBits bullshit, in which case
             * the person testing this NIDS with the smartbits should be flogged
             * to death with a limp noodle
             */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session)););

            idx = (Session *) SafeAlloc(sizeof(Session), p->pkth->ts.tv_sec,
                    NULL);

            if(s4data.reassemble_server)
                (void)ubi_trInitTree(&idx->server.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            if(s4data.reassemble_client)
                (void)ubi_trInitTree(&idx->client.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            idx->server.state = ESTABLISHED;
            idx->client.state = ESTABLISHED;

            idx->server.ip = p->iph->ip_dst.s_addr;
            idx->server.port = p->dp;
            idx->server.isn = pkt_ack-1;
            idx->server.last_ack = pkt_ack;
            idx->server.base_seq = idx->server.last_ack;

            idx->client.ip = p->iph->ip_src.s_addr;
            idx->client.port = p->sp;
            idx->client.isn = pkt_seq-1;
            idx->client.last_ack = pkt_seq;
            idx->client.base_seq = idx->client.last_ack;
            idx->server.win_size = ntohs(p->tcph->th_win);

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;
            idx->session_flags = SSNFLAG_SEEN_CLIENT;
            idx->flush_point = flush_points[fpi];
            break;

        case TH_RES2|TH_SYN: /* nmap fingerprint packet */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session));
                    DebugMessage(DEBUG_STREAM,
                        "nmap fingerprint scan 2SYN packet!\n"););
            idx = (Session *) SafeAlloc(sizeof(Session), p->pkth->ts.tv_sec, NULL);

            if(s4data.reassemble_server)
                (void)ubi_trInitTree(&idx->server.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            if(s4data.reassemble_client)
                (void)ubi_trInitTree(&idx->client.data, /* ptr to the tree head */
                                     DataCompareFunc, /* comparison function */
                                     0);              /* don't allow overwrites */

            idx->server.state = NMAP_FINGERPRINT_2S;
            idx->client.state = NMAP_FINGERPRINT_2S;

            idx->server.ip = p->iph->ip_dst.s_addr;
            idx->server.port = p->dp;

            idx->client.ip = p->iph->ip_src.s_addr;
            idx->client.port = p->sp; /* cp incs by one for each packet */
            idx->client.port++;
            idx->client.isn = pkt_seq;
            idx->server.win_size = ntohs(p->tcph->th_win);

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;

            idx->session_flags = SSNFLAG_SEEN_CLIENT|SSNFLAG_NMAP;
            idx->flush_point = flush_points[fpi];

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"init nmap for sip: 0x%X sp: %d  "
                        "cip: 0x%X cp: %d\n", 
                        idx->server.ip, idx->server.port, 
                        idx->client.ip, idx->client.port););

            break;
        case TH_SYN|TH_RST|TH_ACK|TH_FIN|TH_PUSH|TH_URG:
            if(s4data.ps_alerts)
            {
                /* Full XMAS scan */
                SnortEventqAdd(GENERATOR_SPP_STREAM4,
                        STREAM4_STEALTH_FULL_XMAS,
                        1,
                        0,
                        3,
                        STREAM4_STEALTH_FULL_XMAS_STR,
                        0);
            }

            break;

        case TH_SYN|TH_ACK|TH_URG|TH_PUSH:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_SAPU, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_SAPU_STR, /* msg string */
                        0);
            }

            break;

        case TH_FIN:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_FIN_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_FIN_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case TH_SYN|TH_FIN:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_SYN_FIN_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_SYN_FIN_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case 0:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_NULL_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_NULL_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case TH_FIN|TH_PUSH|TH_URG:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_NMAP_XMAS_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_NMAP_XMAS_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case TH_URG:
        case TH_PUSH:
        case TH_FIN|TH_URG:
        case TH_PUSH|TH_FIN:
        case TH_URG|TH_PUSH:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_VECNA_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_VECNA_SCAN_STR, /* msg string */
                        0);
            }
            
            break;

        case TH_RST:
        case TH_RST|TH_ACK:
            break;

        default: /* 
                  * some kind of non-kosher activity occurred, drop the node 
                  * and flag a portscan
                  */
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_ACTIVITY, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_ACTIVITY_STR, /* msg string */
                        0);

                break;
            }

            return NULL;
    }

    if(idx)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Inserting session into session tree...\n"););

        if(ubi_sptInsert(RootPtr,(ubi_btNodePtr)idx,(ubi_btNodePtr)idx, NULL)
                == FALSE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "sptInsert failed, that's going to "
                        "make life difficult\n"););

            stream4_memory_usage -= sizeof(Session);
            free(idx);
            return NULL;
        }

        pc.tcp_streams++;
    }

    return idx;
}



void DeleteSession(Session *ssn, u_int32_t time)
{
    struct in_addr foo;
    register int s;
    struct tm *lt;
    struct tm *et;
    Session *killme;

    RemoveStreamSession(&sfPerf.sfBase);
    
    if(ssn == NULL)
        return;
    
    if(s4data.track_stats_flag == STATS_HUMAN_READABLE)
    {
        lt = localtime((time_t *) &ssn->start_time);
        s = (ssn->start_time + thiszone) % 86400;

        fprintf(session_log, "[*] Session stats:\n   Start Time: ");
        fprintf(session_log, "%02d/%02d/%02d-%02d:%02d:%02d", lt->tm_mon+1,
                lt->tm_mday, lt->tm_year - 100, s/3600, (s%3600)/60, s%60);

        et = localtime((time_t *) &ssn->last_session_time);
        s = (ssn->last_session_time + thiszone) % 86400;
        fprintf(session_log, "   End Time: %02d/%02d/%02d-%02d:%02d:%02d\n", 
                et->tm_mon+1, et->tm_mday, et->tm_year - 100, s/3600, 
                (s%3600)/60, s%60);

        foo.s_addr = ssn->server.ip;
        fprintf(session_log, "   Server IP: %s  ", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u\n", 
                ssn->server.port, ssn->server.pkts_sent, 
                ssn->server.bytes_sent);
        foo.s_addr = ssn->client.ip;
        fprintf(session_log, "   Client IP: %s  ", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u\n", 
                ssn->client.port, ssn->client.pkts_sent, 
                ssn->client.bytes_sent);

    }
    else if(s4data.track_stats_flag == STATS_MACHINE_READABLE)
    {
        lt = localtime((time_t *) &ssn->start_time);
        s = (ssn->start_time + thiszone) % 86400;

        fprintf(session_log, "[*] Session => Start: ");
        fprintf(session_log, "%02d/%02d/%02d-%02d:%02d:%02d", lt->tm_mon+1,
                lt->tm_mday, lt->tm_year - 100, s/3600, (s%3600)/60, s%60);

        et = localtime((time_t *) &ssn->last_session_time);
        s = (ssn->last_session_time + thiszone) % 86400;
        fprintf(session_log, " End Time: %02d/%02d/%02d-%02d:%02d:%02d", 
                et->tm_mon+1, et->tm_mday, et->tm_year - 100, s/3600, 
                (s%3600)/60, s%60);

        foo.s_addr = ssn->server.ip;
        fprintf(session_log, "[Server IP: %s  ", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u]", 
                ssn->server.port, ssn->server.pkts_sent, 
                ssn->server.bytes_sent);
        foo.s_addr = ssn->client.ip;
        fprintf(session_log, " [Client IP: %s  ", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u]\n", 
                ssn->client.port, ssn->client.pkts_sent, 
                ssn->client.bytes_sent);
    }
    else if(s4data.track_stats_flag == STATS_BINARY)
    {
        BinStats bs;  /* lets generate some BS */

        bs.start_time = ssn->start_time;
        bs.end_time = ssn->last_session_time;
        bs.sip = ssn->server.ip;
        bs.cip = ssn->client.ip;
        bs.sport = ssn->server.port;
        bs.cport = ssn->client.port;
        bs.spackets = ssn->server.pkts_sent;
        bs.cpackets = ssn->client.pkts_sent;
        bs.sbytes = ssn->server.bytes_sent;
        bs.cbytes = ssn->client.bytes_sent;

        WriteSsnStats(&bs);
    }

    if(ubi_trCount(RootPtr))
    {
        killme = (Session *) ubi_sptRemove(RootPtr, (ubi_btNodePtr) ssn);

        DropSession(killme);
    }
}



/*
 * RST 
 *
 * Snort/IDS safe handling of TCP Resets
 *  
 * ignore rules
 * 	if stream tracking is off, ignore resets.
 * 	if stream reassembly is off in the direction of flow, ignore resets.
 * 	if the rst sequence is a duplicate sequence number, ignore it.
 * 	if the rst is on a flow where we have unack'd data, ignore it.
 *  if there is no ack with the reset, ignore it.
 *  if the sequence is > the next expected sequence but still within 
 *      the window , queue it, and ignore it for now.
 *  if the last ack we received is less than our next sequence, we have 
 *      outstanding acks - ignore the reset.
 *      
 *  ignoring a reset does the following:
 * 	the session is not closed.
 * 	if the session is closed by the receiver of the reset, the session will 
 * 	time out.
 * 	if the session is not closed by the receiver, than data will continue to 
 * 	be tracked.
 * 
 * Includes Fix for bug 2161  
 * 9/2/2003
 *
 * 'go to the river called state, eat any of it's acks - but fear the 
 * reset, for it can be poisonous' - man
 * 
 * 
 */
int CheckRst(Session *ssn, int direction, u_int32_t pkt_seq, Packet *p)
{
    Stream *s;
    static StreamPacketData spd;
    spd.seq_num = pkt_seq;

    /* If not tracking state ignore it */
    if( !s4data.stateful_inspection_flag )
        return 0;

    if(direction == FROM_SERVER)
    {
        if( !s4data.reassemble_server ) 
            return 0;

        s = &ssn->server;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"--RST From Server!\n"););
    }
    else
    {
        if( !s4data.reassemble_client ) 
            return 0;

        s = &ssn->client;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"--RST From Client!\n"););
    }

    {
        DEBUG_WRAP(struct in_addr foo;);
        DEBUG_WRAP(foo.s_addr=s->ip; 
                DebugMessage(DEBUG_STREAM, 
                    "--RST packet from %s!\n",inet_ntoa(foo));
                DebugMessage(DEBUG_STREAM, 
                    "--pkt seq: %u   last_ack: %u base-seq: %u next-seq: %u "
                    "bytes-sent: %u bytes-tracked: %u win: %u \n",
                    pkt_seq,s->last_ack,s->base_seq,s->next_seq,s->bytes_sent,
                    s->bytes_tracked,s->win_size););
    }

    /*
     *  We want to make sure the RST has the next valid sequence that 
     *  this side should be sending 
     *  If the pkt_seq < next_seq it's essentially a duplicate 
     *  sequence, and is probably going to be discarded, it certainly 
     *  should be. Also, the base sequence includes the SYN sequence count.
     *  If the packet seq is after the next seq than we should queue the 
     *  packet for later, in case an out of order packet arrives. We 
     *  should also honor the RST-ACK requirements.. but I have to research 
     *  that more.
     *
     *  Ignoring a RST implies we won't shutdown this session due to it.
     *  
     *  This is a standard TCP/IP stack 'in the window' check, but it's 
     *  not always the way stacks handle RST's:
     *  
     *  if(SEQ_LT(pkt_seq,s->base_seq+s->bytes_sent) || 
     *     SEQ_GEQ(pkt_seq,(s->last_ack+s->win_size))) 
     *  
     *  We use a tighter constraint...
     */
    if( !SEQ_EQ(pkt_seq,s->base_seq+s->bytes_sent) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "Bad RST packet, bad sequence or no ack, no cookie!\n");
                DebugMessage(DEBUG_STREAM, "pkt seq: 0x%X   last_ack: 0x%X   "
                    "win: 0x%X\n", pkt_seq, s->last_ack, s->win_size););

        /* we should probably alert here */
        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_EVASIVE_RST, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_EVASIVE_RST_STR, /* msg string */
                    0);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Ignoring a RST (1)...pkt_seq=%u\n",pkt_seq););
        return 0;
    }

    /* At this point if the reset seq + ack flags are ok, we still must not 
     * have any data waiting for an ack to honor the reset right now...
     *
     * 9/2/2003 -  bug 2161
     * 
     * Do not return 1 so fast. This RST might be a retransmission of
     * data that was not acked yet.  If it is, most hosts will reject
     * the RST. Future work should explore this futher.
     *
     * Shai Rubin <shai@cs.wisc.edu>
     */
    if( ubi_sptFind(&s->data,(ubi_btItemPtr)(&spd)) && 
            SEQ_LT(s->last_ack,s->base_seq+s->bytes_sent) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Ignoring a RST (2)...pkt_seq=%u\n",pkt_seq););
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "Not Ignoring a RST...pkt_seq=%u\n",pkt_seq););

    return 1;
}



void DropSession(Session *ssn)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "Dropping session %p\n", ssn););

    if(ssn == NULL)
        return;
    
    DeleteSpd((ubi_trRootPtr)&ssn->server.data);

    DeleteSpd((ubi_trRootPtr)&ssn->client.data);

    if (ssn->preproc_free)
    {
        ssn->preproc_free(ssn->preproc_data);
        ssn->preproc_data = NULL;
        ssn->preproc_free = NULL;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[F] Freeing %d byte session\n", 
                            sizeof(Session)););
    
    stream4_memory_usage -= sizeof(Session);
    free(ssn);
}



void DeleteSpd(ubi_trRootPtr Root)
{    
    (void)ubi_trKillTree(Root, KillSpd);
}


int GetDirection(Session *ssn, Packet *p)
{
    if(p->iph->ip_src.s_addr == ssn->client.ip)
    {
        return FROM_CLIENT;
    }
    else if(((p->tcph->th_flags & TH_NORESERVED) == TH_SYN) &&
            !(ssn->session_flags & SSNFLAG_ESTABLISHED))
    {
        ssn->client.port = p->sp;
        ssn->client.ip   = p->iph->ip_src.s_addr;
        ssn->server.port = p->dp;
        ssn->server.ip   = p->iph->ip_dst.s_addr;
        return FROM_CLIENT;
    }
        
    return FROM_SERVER;
}


Session *GetSession(Packet *p)
{
    Session idx;
    Session *returned;
#ifdef DEBUG
    char flagbuf[9];
    CreateTCPFlagString(p, flagbuf);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Trying to get session...\n"););
    idx.server.ip = p->iph->ip_src.s_addr;
    idx.client.ip = p->iph->ip_dst.s_addr;
    idx.server.port = p->sp;
    idx.client.port = p->dp;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Looking for sip: 0x%X sp: %d  cip: "
                "0x%X cp: %d flags: %s\n", idx.server.ip, idx.server.port, 
                idx.client.ip, idx.client.port, flagbuf););

    returned = (Session *) ubi_sptFind(RootPtr, (ubi_btItemPtr)&idx);

    if(returned == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "GetSession forward didn't work, "
                    "trying backwards...\n"););
        idx.server.ip = p->iph->ip_dst.s_addr;
        idx.client.ip = p->iph->ip_src.s_addr;
        idx.server.port = p->dp;
        idx.client.port = p->sp;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Looking for sip: 0x%X sp: %d  "
                                "cip: 0x%X cp: %d flags: %s\n", idx.server.ip, 
                                idx.server.port, idx.client.ip, idx.client.port,
                                flagbuf););
        returned = (Session *) ubi_sptFind(RootPtr, (ubi_btItemPtr)&idx);
    }

    if(returned == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Unable to find session\n"););
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Found session\n"););
    }

    return returned;

}


void Stream4CleanExitFunction(int signal, void *foo)
{
    if(s4data.track_stats_flag)
    {
        if(s4data.track_stats_flag != STATS_BINARY)
            fclose(session_log);
        else
            if(stats_log != NULL)
                fclose(stats_log->fp);
    }
}



void Stream4RestartFunction(int signal, void *foo)
{
    if(s4data.track_stats_flag)
    {
        if(s4data.track_stats_flag != STATS_BINARY)
            fclose(session_log);
        else
            if(stats_log != NULL)
                fclose(stats_log->fp);
    }
}



void PrintSessionCache()
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "%lu streams active, %u bytes in use\n", 
                            ubi_trCount(RootPtr), stream4_memory_usage););
    return;
}



int PruneSessionCache(u_int32_t thetime, int mustdie, Session *save_me)
{
    Session *idx;
    u_int32_t pruned = 0;

    if(ubi_trCount(RootPtr) == 0)
    {
        return 0;
    }

    if(!mustdie)
    {
        idx = (Session *) ubi_btFirst((ubi_btNodePtr)RootPtr->root);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            if(idx == save_me)
            {
                idx = (Session *) ubi_btNext((ubi_btNodePtr)idx);
                continue;
            }

            if((idx->last_session_time+s4data.timeout) < thetime)
            {
                Session *savidx = idx;

                if(ubi_trCount(RootPtr) > 1)
                {
                    idx = (Session *) ubi_btNext((ubi_btNodePtr)idx);
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "pruning stale session\n"););
                    DeleteSession(savidx, thetime);
                    pruned++;
                }
                else
                {
                    DeleteSession(savidx, thetime);
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                if(idx != NULL && ubi_trCount(RootPtr))
                {
                    idx = (Session *) ubi_btNext((ubi_btNodePtr)idx);
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
        while(mustdie-- &&  ubi_trCount(RootPtr) > 1)
        {
            idx = (Session *) ubi_btLeafNode((ubi_btNodePtr)RootPtr);
            if(idx != save_me)
                DeleteSession(idx, thetime);
        }
#ifdef DEBUG
        if(mustdie) {
            DebugMessage(DEBUG_STREAM, "Emptied out the stream cache"
                         "completely mustdie: %d, memusage: %u\n",
                         mustdie,
                         stream4_memory_usage);
        }
#endif /* DEBUG */

        return 0;
    }

    return 0;
}

/* XXX this function should be reworked so that we don't alloc until
 * we've decided we're actually going to store the packet!
 */
void StoreStreamPkt(Session *ssn, Packet *p, u_int32_t pkt_seq)
{
    Stream *s;
    StreamPacketData *spd;
    StreamPacketData *returned;
    StreamPacketData *foo;

    int direction = GetDirection(ssn, p);

    /* select the right stream */
    if(direction == FROM_CLIENT)
    {
        if(!s4data.reassemble_client)
        {
            return;
        }

        s = &ssn->client;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Storing client packet (%d bytes)\n", 
                    p->pkth->caplen););

        /* Go ahead and detect ttl attacks if we already have one
           ttl from the stream

           since fragroute does this a lot, perhaps we should have a
           counter to avoid false positives.. -- cmg
         */

        if(s4data.ttl_limit)
        {
            if(ssn->ttl && p->iph->ip_ttl < 10)
            { /* have we already set a client ttl? */
                if(abs(ssn->ttl - p->iph->ip_ttl) >= s4data.ttl_limit) 
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_TTL_EVASION, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_TTL_EVASION_STR, /* msg string */
                            0);
                    return;
                }
            } 
            else 
            {
                ssn->ttl = p->iph->ip_ttl; /* first packet we've seen,
                                              lets go ahead and set it. */
            }
        }
    }
    else
    {
        if(!s4data.reassemble_server)
        {
            return;
        }

        s = &ssn->server;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Storing server packet (%d bytes)\n", 
                                p->pkth->caplen););
    }

    /* check for retransmissions of data that's already been ack'd */
    if((pkt_seq < s->last_ack) && (s->last_ack > 0) && 
       (direction == FROM_CLIENT))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"EVASIVE RETRANS: pkt seq: 0x%X "
                                "stream->last_ack: 0x%X\n", pkt_seq, s->last_ack););

        if(s4data.state_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_EVASIVE_RETRANS, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_EVASIVE_RETRANS_STR, /* msg string */
                    0);
        }

        return;
    }

    /* check for people trying to write outside the window */
    if(((pkt_seq + p->dsize - s->last_ack) > s->win_size) && 
       (s->win_size > 0) && direction == FROM_CLIENT)
    {
        /*
         * got data out of the window, someone is FUCKING around or you've got
         * a really crappy IP stack implementaion (hello microsoft!)
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WINDOW VIOLATION: seq: 0x%X  "
                                "last_ack: 0x%X  dsize: %d  " "window: 0x%X\n", 
                                pkt_seq, s->last_ack, p->dsize, s->win_size););

        if(s4data.state_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_WINDOW_VIOLATION, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_WINDOW_VIOLATION_STR, /* msg string */
                    0);
        }

        return;
    }

    if(!WithinSessionLimits(p, s))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[S4] Not within session limits!\n"););
        return;
    }

    
    /* prepare a place to put the data */
    if(s->state >= ESTABLISHED)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] Allocating %d bytes for "
                                "StreamPacketData\n", sizeof(StreamPacketData)););

        spd = (StreamPacketData *) SafeAlloc(sizeof(StreamPacketData), 
                                             p->pkth->ts.tv_sec, ssn);

        spd->seq_num = pkt_seq;
        spd->payload_size = p->dsize;
        spd->cksum = p->tcph->th_sum;

        /* attach the packet here */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] Allocating %u bytes for packet\n", 
                                p->pkth->caplen););

        spd->pkt = (u_int8_t *) SafeAlloc(p->pkth->caplen, p->pkth->ts.tv_sec, 
                                          ssn);
        spd->pkt_size = p->pkth->caplen;

        /* copy the packet */
        memcpy(spd->pkt, p->pkt, p->pkth->caplen);

        /* copy the packet header */
        memcpy(&spd->pkth, p->pkth, sizeof(SnortPktHeader));

        /* set the pointer to the stored packet payload */
        spd->payload = spd->pkt + (p->data - p->pkt);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WARNING: Data on unestablished "
                    "session state: %d)!\n", s->state););
        return;
    }

    /* check for retransmissions */
    returned = (StreamPacketData *) ubi_sptFind(&s->data, (ubi_btItemPtr)spd);

    if(returned != NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "WARNING: returned packet not null\n"););
        if(returned->payload_size == p->dsize)
        {
            /* check to see if the data has been ack'd */
            if(s->last_ack < pkt_seq + p->dsize)
            {
                /* retransmission of un-ack'd packet, chuck the old one 
                 * and put in the new one
                 * --------------------------------------------------
                 * We have to be aware of two packets sent one right
                 * after the other
                 *
                 * One packet sends us the data they want the remote
                 * host to recieve, the next sends us the data they
                 * want the IDS to incorrectly pick up.
                 *
                 * This gets us into the *nasty* problem of how to
                 * detect differing data.
                 *
                 * Hopefully this doesn't occur too much in real life
                 * because this check will make life slow in the
                 * normal case.  Of course it will just be an extra
                 * check on port 80 check for pattern matching which
                 * already hurts us enough as is :-)
                 *
                 */

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Checking Packet Contents versus Packet Store\n"););

                if(returned->cksum != p->tcph->th_sum)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "TCP Checksums not equal\n"););


                    stream4_memory_usage -= spd->pkt_size;
                    free(spd->pkt);

                    stream4_memory_usage -= sizeof(StreamPacketData);
                    free(spd);

                    if(s4data.evasion_alerts)
                    {
                        SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                                STREAM4_EVASIVE_RETRANS_DATA, /* SID */
                                1,                      /* Rev */
                                0,                      /* classification */
                                3,                      /* priority (low) */
                                STREAM4_EVASIVE_RETRANS_DATA_STR,/*msg string */
                                0);
                    }

                    return;
                } 
                else 
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "TCP Checksums equal..."
                                " returning; see comment in src\n"););
                    /*
                     * Possible Research chance:
                     *
                     *  How easy is it to fool IDSes with differening
                     *  payloads that have the same checksums to the
                     *  same IPs
                     */

                    stream4_memory_usage -= spd->pkt_size;
                    free(spd->pkt);

                    stream4_memory_usage -= sizeof(StreamPacketData);
                    free(spd);

                    return;
                }
            }
            else
            {
                /* screw it, we already ack'd this data */
                StreamSegmentSub(s, spd->payload_size);

                stream4_memory_usage -= spd->pkt_size;
                free(spd->pkt);

                stream4_memory_usage -= sizeof(StreamPacketData);
                free(spd);

                if(s4data.state_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_EVASIVE_RETRANS, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_EVASIVE_RETRANS_STR, /* msg string */
                            0);
                }
                return;
            }
        }
        else if(returned->payload_size < p->dsize)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Duplicate packet with forward overlap\n"););

            /* check to see if this one's been ack'd */
            if(s->last_ack > pkt_seq + p->dsize)
            {
                StreamSegmentSub(s, spd->payload_size);

                /* screw it, we already ack'd this data */
                stream4_memory_usage -= spd->pkt_size;
                free(spd->pkt);

                stream4_memory_usage -= sizeof(StreamPacketData);
                free(spd);

                if(s4data.evasion_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_FORWARD_OVERLAP, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_FORWARD_OVERLAP_STR, /* msg string */
                            0);
                }

                return;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Replacing un-ack'd segment in Packet Store\n"););

                foo = (StreamPacketData *) ubi_sptRemove(&s->data, 
                        (ubi_btNodePtr) returned);                

                StreamSegmentSub(s, foo->payload_size);


                stream4_memory_usage -= foo->pkt_size;
                free(foo->pkt);

                stream4_memory_usage -= sizeof(StreamPacketData);
                free(foo);
            }
        }
        else if(returned->payload_size > p->dsize)
        {
            /* check to see if this one's been ack'd */
            if(s->last_ack > pkt_seq + p->dsize)
            {
                StreamSegmentSub(s, spd->payload_size);

                /* screw it, we already ack'd this data */
                stream4_memory_usage -= spd->pkt_size;
                free(spd->pkt);

                stream4_memory_usage -= sizeof(StreamPacketData);
                free(spd);

                if(s4data.state_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_EVASIVE_RETRANS, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_EVASIVE_RETRANS_STR, /* msg string */
                            0);
                }
                return;
            }
            else
            {
                /* Some tool will probably have the following scenario one day.
                 * send a bunch of 1 byte packets that the remote host should 
                 * see and start acking and then follow that up with one 
                 * big packet
                 *
                 * To defeat this, we have to see if the contents of
                 * the big packet match up with the ton of dinky packets...
                 *
                 * Instead of just going to look for every damn one of
                 * the packets, lets just compare the timestamp of our
                 * current packet versus the retransmitted one.
                 *
                 * We could probably detect all the fun retransmission
                 * games this way.
                 */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Checking if we are retranmitting too fast\n"););

                if(RetransTooFast(&returned->pkth.ts, 
                            (struct timeval *) &p->pkth->ts))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "Generating packets retranmissions "
                                "faster than we should\n"););

                    stream4_memory_usage -= spd->pkt_size;
                    free(spd->pkt);

                    stream4_memory_usage -= sizeof(StreamPacketData);
                    free(spd);

                    if(s4data.evasion_alerts)
                    {
                        SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                                STREAM4_EVASIVE_RETRANS_DATASPLIT, /* SID */
                                1,                      /* Rev */
                                0,                      /* classification */
                                3,                      /* priority (low) */
                                STREAM4_EVASIVE_RETRANS_DATASPLIT_STR, /* msg string */
                                0);
                    }
                    return;
                } 
                else 
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "Replacing un-ack'd segment in Packet Store\n"););

                    foo = (StreamPacketData *) ubi_sptRemove(&s->data, 
                            (ubi_btNodePtr) returned);

                    stream4_memory_usage -= foo->pkt_size;
                    free(foo->pkt);

                    stream4_memory_usage -= sizeof(StreamPacketData);
                    free(foo);
                }

            }
        }
    }

    if(ubi_sptInsert(&s->data,(ubi_btNodePtr)spd,(ubi_btNodePtr)spd, NULL)
       == FALSE)
    {
        LogMessage("sptInsert failed, that sucks\n");
        return;
    }

    p->packet_flags |= PKT_STREAM_INSERT;

    return;
}



void FlushStream(Stream *s, Packet *p, int direction)
{
    int stream_size;

    int gotevent = 0;

    sfPerf.sfBase.iStreamFlushes++;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "FlushStream Entered:"
                "last_ack(%u) base_seq(%u) trCount(%u)\ng",
                s->last_ack, s->base_seq, ubi_trCount(&s->data)););

    stream_size = s->last_ack - s->base_seq;

    /* 
     ** FINs consume one byte, but they have no data.
     **
     ** NOTE:
     **   This already appears to be compensated for when we receive FINS,
     **   and this causes an off-by-one bug when implemented.
     */
    /*if(s->state == FIN_WAIT_2 || s->state == TIME_WAIT) stream_size--;*/

    if(stream_size >= MAX_STREAM_SIZE)
    {
#ifdef DEBUG        
        DebugMessage(DEBUG_STREAM,
                "stream_size(%u) > MAX_STREAM_SIZE(%u)\n",
                stream_size, MAX_STREAM_SIZE);

        DebugMessage(DEBUG_STREAM,
                "Adjusting s->base_seq(%u) -> %u %u\n",
                s->base_seq, s->last_ack - MAX_STREAM_SIZE,
                s->last_ack - (MAX_STREAM_SIZE));

#endif /* DEBUG */
        stream_size = MAX_STREAM_SIZE - 1;
        s->base_seq = s->last_ack - stream_size;
    }

    if(stream_size > 0 && ubi_trCount(&s->data))
    {
        /* put the stream together into a packet or something */
        if(BuildPacket(s, stream_size, p, direction))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Passing large packet "
                        "on 0 size stream cache\n"););
            return;
        }

        /* If we aren't within session limits, we can try to build a
         * packet and end up with no data */
        if(stream_pkt->dsize > 0)
        {
            gotevent = Preprocess(stream_pkt);

            if(s4data.zero_flushed_packets)
                bzero(stream_pkt->data, stream_pkt->dsize);

            if(gotevent)
            {
                LogStream(s);
            }
        }

        SegmentCleanTraverse(s);
        return;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Passing large packet on "
                    "0 size stream cache\n"););
    }

    s->bytes_tracked = 0;
    DeleteSpd(&s->data);
}



/**
 * Flush the side of the TCP stream that just caused an alert.
 *
 * This function is exported for the detection engine.
 *
 * This routine takes a packet, logs out the stream packets ( so that
 * we have original payloads around ), and then updates the stream
 * tracking sequence numbers so that
 * 
 * @param p Packet to flush the stream reassembler on
 * 
 * @return the number of packets that have been flushed from the stream reassembler
 */
int AlertFlushStream(Packet *p)
{
    Session *ssn = p->ssnptr;
    Stream *stream;
    int nodecount = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Flushing stream due to an alert!\n"););

    if(NotForStream4(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Don't Flush a Rebuilt Stream\n"););
        return 0;
    }

    if(ssn == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Nothing to Flush!\n"););
        return 0;
    }

    if(GetDirection(ssn, p) == FROM_SERVER)
    {
        stream = &ssn->server;

        if(s4data.reassemble_server)
        {
            FlushStream(stream, p, NO_REVERSE);
        }
        else
        { 
            /*
            **  We handle this part of deleting the stream, because
            **  FlushStream() didn't handle it for us.
            */
            DeleteSpd(&stream->data);
            stream->bytes_tracked = 0;
        }
    }
    else
    {
        stream = &ssn->client;

        if(s4data.reassemble_client)
        {
            FlushStream(stream, p, NO_REVERSE);
        }
        else
        { 
            /*
            **  We handle this part of deleting the stream, because
            **  FlushStream() didn't handle it for us.
            */
            DeleteSpd(&stream->data);
            stream->bytes_tracked = 0;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[AFS] Bytes Tracked: %u\n", 
                stream->bytes_tracked););
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[AFS] Bytes Tracked: %u\n", 
                stream->bytes_tracked););

    if(p->tcph)
    {
        stream->base_seq = ntohl(p->tcph->th_seq) + p->dsize;
        stream->last_ack = stream->base_seq;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Moved the base_seq to %u!\n",
                stream->base_seq););

    return nodecount;
}

/** 
 * Log out the Stream if possible
 *
 * only works with pcap currently
 *
 * @todo make this work with a newer output subsystem
 * 
 * @param s stream to log the data from
 * 
 * @return number of nodes in the data
 */
int LogStream(Stream *s)
{
    int nodecount = 0;
    
    if((pv.log_bitmap & LOG_TCPDUMP) && s4data.log_flushed_streams)
    {
        nodecount = ubi_trCount(&s->data);
        (void)ubi_trTraverse(&s->data, LogTraverse, s);
    }

    return nodecount;
}



void InitStream4Pkt()
{
    stream_pkt->pkth = calloc(sizeof(SnortPktHeader)+
                              ETHERNET_HEADER_LEN +
                              SPARC_TWIDDLE + IP_MAXPACKET,
                              sizeof(char));

    stream_pkt->pkt = ((u_int8_t *)stream_pkt->pkth) + sizeof(SnortPktHeader);
    stream_pkt->eh = (EtherHdr *)((u_int8_t *)stream_pkt->pkt + SPARC_TWIDDLE);
    stream_pkt->iph =
        (IPHdr *)((u_int8_t *)stream_pkt->eh + ETHERNET_HEADER_LEN);
    stream_pkt->tcph = (TCPHdr *)((u_int8_t *)stream_pkt->iph + IP_HEADER_LEN);    

    stream_pkt->data = (u_int8_t *)stream_pkt->tcph + TCP_HEADER_LEN;

    /* stream_pkt->data is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + TCP_HEADER_LEN + ETHERNET_HEADER_LEN)
     *  in size
     *
     * This is MAX_STREAM_SIZE
     */

    stream_pkt->eh->ether_type = htons(0x0800);
    SET_IP_VER(stream_pkt->iph, 0x4);
    SET_IP_HLEN(stream_pkt->iph, 0x5);
    stream_pkt->iph->ip_proto = IPPROTO_TCP;
    stream_pkt->iph->ip_ttl   = 0xF0;
    stream_pkt->iph->ip_len = 0x5;
    stream_pkt->iph->ip_tos = 0x10;

    SET_TCP_OFFSET(stream_pkt->tcph,0x5);
    stream_pkt->tcph->th_flags = TH_PUSH|TH_ACK;
}



/** 
 * Build a new stream packet from 
 * 
 * @param s Stream storage variables
 * @param stream_size size of the newly assembled stream ( should be less than 2^16 - 41
 * @param p packet that caused us to flush
 * @param direction which are we flushing
 *
 * @returns 0 on success, -1 if we didn't get enough data to create the packet
 */
int BuildPacket(Stream *s, u_int32_t stream_size, Packet *p, int direction)
{
    BuildData bd;
    int zero_size = 1500;
    Session *ssn;
    u_int32_t ip_len; /* total length of the IP datagram */
    ip_len = stream_size + IP_HEADER_LEN + TCP_HEADER_LEN;

    stream_pkt->pkth->ts.tv_sec = p->pkth->ts.tv_sec;
    stream_pkt->pkth->ts.tv_usec = p->pkth->ts.tv_usec;

    stream_pkt->pkth->caplen = ip_len + ETHERNET_HEADER_LEN;
    stream_pkt->pkth->len    = stream_pkt->pkth->caplen;

    stream_pkt->iph->ip_len = htons((u_short) ip_len);

    if(direction == REVERSE)
    {
        if(p->eh != NULL)
        {
            memcpy(stream_pkt->eh->ether_dst, p->eh->ether_src, 6);
            memcpy(stream_pkt->eh->ether_src, p->eh->ether_dst, 6);
        }

        stream_pkt->tcph->th_sport = p->tcph->th_dport;
        stream_pkt->tcph->th_dport = p->tcph->th_sport;
        stream_pkt->iph->ip_src.s_addr = p->iph->ip_dst.s_addr;
        stream_pkt->iph->ip_dst.s_addr = p->iph->ip_src.s_addr;
        stream_pkt->sp = p->dp;
        stream_pkt->dp = p->sp;
    }
    else
    {
        if(p->eh != NULL)
        {
            memcpy(stream_pkt->eh->ether_dst, p->eh->ether_dst, 6);
            memcpy(stream_pkt->eh->ether_src, p->eh->ether_src, 6);
        }

        stream_pkt->tcph->th_sport = p->tcph->th_sport;
        stream_pkt->tcph->th_dport = p->tcph->th_dport;
        stream_pkt->iph->ip_src.s_addr = p->iph->ip_src.s_addr;
        stream_pkt->iph->ip_dst.s_addr = p->iph->ip_dst.s_addr;
        stream_pkt->sp = p->sp;
        stream_pkt->dp = p->dp;
    }

    stream_pkt->tcph->th_seq = p->tcph->th_seq;
    stream_pkt->tcph->th_ack = p->tcph->th_ack;
    stream_pkt->tcph->th_win = p->tcph->th_win;

    s4data.stop_traverse = 0;

    bd.stream = s;
    bd.buf = stream_pkt->data;
    bd.total_size = 0;

    /* walk the packet tree (in order) and rebuild the app layer data */
    (void)ubi_trTraverse(&s->data, TraverseFunc, &bd);

    if(bd.total_size < stream_size)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "bd.total_size(%u) < stream_size(%u):"
                    "Incomplete segment -- packet loss or weird\n",
                    bd.total_size, stream_size););

        /* This is probably because we were past our session limits --
           there's nothing of value in this packet */
        if(bd.total_size == 0)
        {
            stream_pkt->dsize = 0;
            return -1;
        }
    }
    else if(bd.total_size > stream_size)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "stream_size(%u) < bd.total_size(%u):"
                    "Overlapping segments -- packet loss or weird\n",
                    stream_size, bd.total_size););
    }

    /* This is set in TraverseFunc when we reach a point that we
     * haven't ack'd to yet. Let's just go catch it next time.
     */
    if(s4data.stop_traverse)
    {
        if(s4data.stop_seq < s->base_seq)
        {
            stream_size = s->base_seq - s4data.stop_seq;
        }
        else
        {
            stream_size = s4data.stop_seq - s->base_seq;
        }

        /*
        **  Final sanity check for stream_size.  Make sure that the stream_size is
        **  not bigger than our buffer.
        */
        if(stream_size >= MAX_STREAM_SIZE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Truncating %d bytes from stream",
                        stream_size - MAX_STREAM_SIZE););

            stream_size = MAX_STREAM_SIZE - 1;
        }

        ip_len = IP_HEADER_LEN + TCP_HEADER_LEN + stream_size;

        stream_pkt->dsize = stream_size;

        stream_pkt->pkth->caplen = ETHERNET_HEADER_LEN + ip_len;
        stream_pkt->pkth->len = stream_pkt->pkth->caplen;

        stream_pkt->iph->ip_len = htons( (u_short) ip_len );
    }
    else
    {
        stream_pkt->dsize = stream_size;
    }

    s4data.stop_traverse = 0;

    stream_pkt->tcp_option_count = 0;
    stream_pkt->tcp_lastopt_bad = 0;
    stream_pkt->packet_flags = (PKT_REBUILT_STREAM|PKT_STREAM_EST);

    ssn = p->ssnptr;
    stream_pkt->ssnptr = p->ssnptr;

    stream_pkt->streamptr = (void *) s;

    if(stream_pkt->sp == ssn->client.port)
    {
        stream_pkt->packet_flags |= PKT_FROM_CLIENT;
    }
    else
    {
        stream_pkt->packet_flags |= PKT_FROM_SERVER;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "Built packet to %s from %x with %u byte payload, "
                "Direction: %s\n",
                inet_ntoa(stream_pkt->iph->ip_src),
                stream_pkt->iph->ip_dst,
                stream_pkt->dsize,
                (stream_pkt->packet_flags & PKT_FROM_SERVER)
                ? "from_server" : "from_client"););

    pc.rebuilt_tcp++;

#ifdef DEBUG
    if(stream_pkt->packet_flags & PKT_FROM_CLIENT)
    {
        DebugMessage(DEBUG_STREAM, "packet is from client!\n");
    }

    if(stream_pkt->packet_flags & PKT_FROM_SERVER)
    {
        DebugMessage(DEBUG_STREAM, "packet is from server!\n");
    }

    ClearDumpBuf();
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    PrintIPPkt(stdout, IPPROTO_TCP, stream_pkt);
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    ClearDumpBuf();
    /*printf("Printing app buffer at %p, size %d\n", 
      stream_pkt->data, stream_pkt->dsize);
      PrintNetData(stdout, stream_pkt->data, stream_pkt->dsize);
      ClearDumpBuf();*/
#endif

    /* are we within our data loss limits? */
    if(abs(stream_pkt->dsize - bd.total_size) >= s4data.flush_data_diff_size)
    {
        /* leave a null packet if we tried to reassemble and failed */
        if(s4data.zero_flushed_packets)
        {
            /* stream_size is uint so can't be negative */
            if(stream_size && stream_size < zero_size)
            {
                zero_size = stream_size;
            }

            if(zero_size > 0)
                bzero(stream_pkt->data, zero_size);
        }
    }

    return 0;
}


int CheckPorts(u_int16_t port1, u_int16_t port2)
{
    switch(s4_emergency.status)
    {
        case OPS_NORMAL:
            if(s4data.assemble_ports[port1] || s4data.assemble_ports[port2])
            {
                return 1;
            }
            break;

        case OPS_SELF_PRESERVATION:
            if(s4data.emergency_ports[port1] || s4data.emergency_ports[port2])
            {
                return 1;
            }
            break;
    }

    return 0;
}


void OpenStatsFile()
{
    time_t curr_time;      /* place to stick the clock data */
    char logdir[STD_BUF];
    int value;
    StatsLogHeader hdr;

    bzero(logdir, STD_BUF);
    curr_time = time(NULL);

    if(stats_log->filename[0] == '/')
        value = snprintf(logdir, STD_BUF, "%s.%lu", stats_log->filename, 
                         (unsigned long)curr_time);
    else
        value = snprintf(logdir, STD_BUF, "%s/%s.%lu", pv.log_dir, 
                         stats_log->filename, (unsigned long)curr_time);

    if(value == -1)
    {
        FatalError("ERROR: log file logging path and file name are "
                   "too long, aborting!\n");
    }

    printf("stream4:OpenStatsFile() Opening %s\n", logdir);

    if((stats_log->fp=fopen(logdir, "w+")) == NULL)
    {
        FatalError("stream4:OpenStatsFile(%s): %s\n", logdir, strerror(errno));
    }

    hdr.magic = STATS_MAGIC;
    hdr.version_major = 1;
    hdr.version_minor = 81;
    hdr.timezone = 1;

    if(fwrite((char *)&hdr, sizeof(hdr), 1, stats_log->fp) != 1)
    {
        FatalError("stream4:OpenStatsFile(): %s\n", strerror(errno));
    }
        
    fflush(stats_log->fp);

    /* keep a copy of the filename for later reference */
    if(stats_log->filename != NULL)
    {
        free(stats_log->filename);

        stats_log->filename = strdup(logdir);
    }

    return;
}



void WriteSsnStats(BinStats *bs)
{
    fwrite(bs, sizeof(BinStats), 1, stats_log->fp);
    fflush(stats_log->fp);
    return;
}

static void TcpAction(Session *ssn, Packet *p, int action, int direction, 
                      u_int32_t pkt_seq, u_int32_t pkt_ack)
{
    if(action == ACTION_NOTHING)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "returning -- action nothing\n"););
        return;
    }
    else 
    {
        if((action & ACTION_SET_SERVER_ISN) &&
                (ssn->session_flags & SSNFLAG_MIDSTREAM))
        {
            /* Someone convinced us the session was going and then is
             * trying to convince us that we should be tracking this
             * session -- the server has the best chance of knowing
             * what it's really seeing.
             */

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Midstream session SYN-ACK; setting seqs;" 
                        "removing midstream notification\n"););
            ssn->client.last_ack = pkt_ack;
            ssn->server.last_ack = pkt_seq;

            ssn->server.base_seq = ssn->server.last_ack;
            ssn->client.base_seq = ssn->client.last_ack;

            /* Once we reach here, the session is no longer a
               midstream session */

            //ssn->session_flags &= (SSNFLAG_ALL ^ SSNFLAG_MIDSTREAM);
        }      
        else if(action & ACTION_SET_SERVER_ISN)
        {
            ssn->server.isn = pkt_seq;
            ssn->client.win_size = ntohs(p->tcph->th_win);

            if(pkt_ack == (ssn->client.isn+1))
            {
                ssn->client.last_ack = ssn->client.isn+1;
            }
            else
            {
                /* we got a messed up response from the server */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Got unexpected SYN ACK from server!\n");
                        DebugMessage(DEBUG_STREAM, 
                            "expected: 0x%X   received: 0x%X\n"););
                ssn->client.last_ack = pkt_ack;
            }
        }

        /* complete a three way handshake */
        if(action & ACTION_COMPLETE_TWH)
        {
            /*
            **  Set a packet flag to say that the TWH has been
            **  completed.
            */
            p->packet_flags |= PKT_STREAM_TWH;

            /* this should be isn+1 */
            if(pkt_ack == ssn->server.isn+1)
            {
                ssn->server.last_ack = ssn->server.isn+1;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WARNING: Fishy TWH from client "
                            "(0x%X:%d->0x%X:%d) (ack: 0x%X  isn: 0x%X)\n", 
                            p->iph->ip_src.s_addr, p->sp, p->iph->ip_dst.s_addr, 
                            p->dp, pkt_ack, ssn->server.isn););

                ssn->server.last_ack = pkt_ack;
            }

            ssn->server.base_seq = ssn->server.last_ack;
            ssn->client.base_seq = ssn->client.last_ack;
        }

        /* 
         * someone sent data in their SYN packet, classic sign of someone
         * doing bad things (or a bad ip stack/piece of equipment)
         */
        if(action & ACTION_DATA_ON_SYN)
        {
            if(p->tcph->th_flags & TH_SYN)
            {
                /* alert... */
                if(s4data.evasion_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_DATA_ON_SYN, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_DATA_ON_SYN_STR, /* msg string */
                            0);
                }

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Data on SYN packet!\n"););
                return;
            }
        }

        if(action & ACTION_INC_PORT)
        {
            ssn->client.port++;
        }

        /* client sent some data */
        if(action & ACTION_ACK_CLIENT_DATA)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "client.base_seq(%u) client.last_ack(%u) offset(%u)\n",
                        ssn->client.base_seq,ssn->client.last_ack,
                        (ssn->client.last_ack - ssn->client.base_seq)););

            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            /* Going way out of our way to avoid an off by 1. */
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) && 
                    (ssn->client.next_seq + 1 == pkt_ack))
            {
                /* the fin consumes one byte of the sequence that
                 * really doesn't posses data */                
                ssn->client.last_ack = pkt_ack - 1;
            }
            else if(SEQ_LT(ssn->client.last_ack, pkt_ack))
            {
                /*
                 **   This assumes that the server is not malicious,
                 **   since it could fake large acks so we would ignore
                 **   data later on.
                 */
                ssn->client.last_ack = pkt_ack;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "client.base_seq(%u) "
                        "client.last_ack(%u) client.next_seq(%u)\n",
                        ssn->client.base_seq,ssn->client.last_ack, 
                        ssn->client.next_seq););

            if(ssn->session_flags & SSNFLAG_ESTABLISHED)
            {
                Stream *s;

                s = &ssn->client;

                if((ssn->client.last_ack - ssn->client.base_seq) > ssn->flush_point 
                        && ubi_trCount(&s->data) > 1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Flushing Client packet buffer "
                                "(%d bytes a: 0x%X b: 0x%X pkts: %d)\n",
                                (ssn->client.last_ack - ssn->client.base_seq), 
                                ssn->client.last_ack, ssn->client.base_seq,
                                ubi_trCount(&s->data)););

                    if(s4data.reassemble_client)
                    {
                        FlushStream(&ssn->client, p, REVERSE);
                    }

                    ssn->client.base_seq = ssn->client.last_ack;
                } 
                else 
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "%d (%d) bytes to go before we flush: "
                                "(%d) segments stored\n",
                                (ssn->flush_point-
                                    (ssn->client.last_ack - ssn->client.base_seq)),
                                (ssn->client.last_ack - ssn->client.base_seq),
                                ubi_trCount(&ssn->client.data)););
                }
            }
        }

        /* server sent some data */
        if(action & ACTION_ACK_SERVER_DATA)
        {
            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) &&
                    (ssn->server.next_seq + 1 == pkt_ack))
            {
                /* Going way out of our way to avoid an off by 1. */
                ssn->server.last_ack = pkt_ack - 1;
            }
            else if(SEQ_LT(ssn->server.last_ack, pkt_ack))
            {
                ssn->server.last_ack = pkt_ack;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "server.base_seq(%u) "
                        "server.last_ack(%u) server.next_seq(%u)\n",
                        ssn->server.base_seq,ssn->server.last_ack, 
                        ssn->server.next_seq););

            if(ssn->session_flags & SSNFLAG_ESTABLISHED)
            {
                Stream *s;

                s = &ssn->server;

                if((ssn->server.last_ack - ssn->server.base_seq) > ssn->flush_point
                        && ubi_trCount(&s->data) > 1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Flushing Server packet buffer "
                                "(%d bytes a: 0x%X b: 0x%X)\n",
                                (ssn->server.last_ack - ssn->server.base_seq),
                                ssn->server.last_ack, ssn->server.base_seq););

                    if(s4data.reassemble_server)
                    {
                        FlushStream(&ssn->server, p, REVERSE);
                    }

                    ssn->server.base_seq = ssn->server.last_ack;
                }
            }
        }

        if(s4data.ps_alerts && (action & ACTION_ALERT_NMAP_FINGERPRINT))
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_STEALTH_NMAP_FINGERPRINT, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_STEALTH_NMAP_FINGERPRINT_STR, /* msg string */
                    0);
            return;
        }

        if(action & ACTION_FLUSH_SERVER_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing server stream, ending "
                        "session: %d\n", s4data.reassemble_server););

            if(s4data.reassemble_server)
            {
                if(direction == FROM_SERVER)
                {
                    FlushStream(&ssn->server, p, NO_REVERSE);
                }
                else
                {
                    FlushStream(&ssn->server, p, REVERSE);
                }
            }

            p->packet_flags |= PKT_STREAM_EST;
        }

        if(action & ACTION_FLUSH_CLIENT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing client stream, ending "
                        "session\n"););

            if(s4data.reassemble_client)
            {
                if(direction == FROM_CLIENT)
                {
                    FlushStream(&ssn->client, p, NO_REVERSE);
                }
                else
                {
                    FlushStream(&ssn->client, p, REVERSE);
                }
            }

            p->packet_flags |= PKT_STREAM_EST;
        }

        if(action & ACTION_DROP_SESSION)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Dumping session\n"););
            DeleteSession(ssn, p->pkth->ts.tv_sec);
            p->ssnptr = NULL;
        }
    }
}

static void TcpActionAsync(Session *ssn, Packet *p, int action, int direction, 
                           u_int32_t pkt_seq, u_int32_t pkt_ack)
{
    if(direction == FROM_CLIENT)
    {
        if(!ssn->client.isn)
        {
            ssn->client.isn = pkt_seq;
        }

        ssn->client.last_ack = pkt_seq;

    }
    else
    {
        if(!ssn->server.isn)
        {
            ssn->server.isn = pkt_seq;
        }

        ssn->server.last_ack = pkt_seq;
    }


    if(action == ACTION_NOTHING)
    {
        return;
    }
    else 
    {
        if(action & ACTION_SET_SERVER_ISN)
        {
            ssn->server.isn = pkt_seq;
            ssn->client.win_size = ntohs(p->tcph->th_win);

            if(pkt_ack == (ssn->client.isn+1))
            {
                ssn->client.last_ack = ssn->client.isn+1;
            }
            else
            {
                /* we got a messed up response from the server */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Got unexpected SYN ACK from server!\n");
                        DebugMessage(DEBUG_STREAM, 
                            "expected: 0x%X   received: 0x%X\n"););
                ssn->client.last_ack = pkt_ack;
            }
        }

        /* complete a three way handshake */
        if(action & ACTION_COMPLETE_TWH)
        {
            /*
            **  Set a packet flag to say that the TWH has been
            **  completed.
            */
            p->packet_flags |= PKT_STREAM_TWH;

            /* this should be isn+1 */
            if(pkt_ack == ssn->server.isn+1)
            {
                ssn->server.last_ack = ssn->server.isn+1;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Fishy TWH from client "
                            "(0x%X:%d->0x%X:%d) (ack: 0x%X  isn: 0x%X)\n", 
                            p->iph->ip_src.s_addr, p->sp, p->iph->ip_dst.s_addr, 
                            p->dp, pkt_ack, ssn->server.isn););

                ssn->server.last_ack = pkt_ack;
            }

            ssn->server.base_seq = ssn->server.last_ack;
            ssn->client.base_seq = ssn->client.last_ack;
        }

        /* 
         * someone sent data in their SYN packet, classic sign of someone
         * doing bad things (or a bad ip stack/piece of equipment)
         */
        if(action & ACTION_DATA_ON_SYN)
        {
            if(p->tcph->th_flags & TH_SYN)
            {
                /* alert... */
                if(s4data.evasion_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_DATA_ON_SYN, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_DATA_ON_SYN_STR, /* msg string */
                            0);
                }

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Data on SYN packet!\n"););
                return;
            }
        }

        if(action & ACTION_INC_PORT)
        {
            ssn->client.port++;
        }

        /* client sent some data */
        if(action & ACTION_ACK_CLIENT_DATA)
        {
            Stream *s;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "client.base_seq(%u) client.last_ack(%u)\n",
                        ssn->client.base_seq,ssn->client.last_ack););

            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            /* Going way out of our way to avoid an off by 1. */
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) && 
                    (ssn->client.next_seq + 1 == pkt_ack))
            {
                /* the fin consumes one byte of the sequence that
                 * really doesn't posses data */                
                ssn->client.last_ack = pkt_ack - 1;
            }
            else
            {
                ssn->client.last_ack = pkt_ack;
            }

            s = &ssn->client;

            if((ssn->client.last_ack - ssn->client.base_seq) > ssn->flush_point 
                    && ubi_trCount(&s->data) > 1)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "Flushing Client packet buffer "
                            "(%d bytes a: 0x%X b: 0x%X pkts: %d)\n",
                            (ssn->client.last_ack - ssn->client.base_seq), 
                            ssn->client.last_ack, ssn->client.base_seq,
                            ubi_trCount(&s->data)););

                if(s4data.reassemble_client)
                {
                    FlushStream(&ssn->client, p, REVERSE);
                }

                ssn->client.base_seq = ssn->client.last_ack;
            }
        }

        /* server sent some data */
        if(action & ACTION_ACK_SERVER_DATA)
        {
            Stream *s;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "server.base_seq(%u) server.last_ack(%u)\n",
                        ssn->server.base_seq,ssn->server.last_ack););

            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) &&
                    (ssn->server.next_seq + 1 == pkt_ack))
            {
                /* Going way out of our way to avoid an off by 1. */
                ssn->server.last_ack = pkt_ack - 1;
            }
            else
            {
                ssn->server.last_ack = pkt_ack;
            }


            s = &ssn->server;

            if((ssn->server.last_ack - ssn->server.base_seq) > ssn->flush_point
                    && ubi_trCount(&s->data) > 1)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "Flushing Server packet buffer "
                            "(%d bytes a: 0x%X b: 0x%X)\n",
                            (ssn->server.last_ack - ssn->server.base_seq),
                            ssn->server.last_ack, ssn->server.base_seq););

                if(s4data.reassemble_server)
                {
                    FlushStream(&ssn->server, p, REVERSE);
                }

                ssn->server.base_seq = ssn->server.last_ack;
            }
        }

        if(s4data.ps_alerts && (action & ACTION_ALERT_NMAP_FINGERPRINT))
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_STEALTH_NMAP_FINGERPRINT, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_STEALTH_NMAP_FINGERPRINT_STR, /* msg string */
                    0);
            return;
        }

        if(action & ACTION_FLUSH_SERVER_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing server stream, ending "
                        "session: %d\n", s4data.reassemble_server););

            if(s4data.reassemble_server)
            {
                if(direction == FROM_SERVER)
                {
                    FlushStream(&ssn->server, p, NO_REVERSE);
                }
                else
                {
                    FlushStream(&ssn->server, p, REVERSE);
                }
            }
        }

        if(action & ACTION_FLUSH_CLIENT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing client stream, ending "
                        "session\n"););

            if(s4data.reassemble_client)
            {
                if(direction == FROM_CLIENT)
                {
                    FlushStream(&ssn->client, p, NO_REVERSE);
                }
                else
                {
                    FlushStream(&ssn->client, p, REVERSE);
                }
            }
        }

        if(action & ACTION_DROP_SESSION)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Dumping session\n"););
            DeleteSession(ssn, p->pkth->ts.tv_sec);
            p->ssnptr = NULL;
        }
    }
}
