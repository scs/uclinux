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

/* $Id$ */

/* spo_unified 
 * 
 * Purpose:
 *
 * This plugin generates the new unified alert and logging formats
 *
 * Arguments:
 *   
 * filename of the alert and log spools
 *
 * Effect:
 *
 * Packet logs are written (quickly) to a unified output file
 *
 * Comments:
 *
 * The future...
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <time.h>

#include "decode.h"
#include "rules.h"
#include "util.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "stream.h"
#include "event.h"
#include "generators.h"
#include "snort_packet_header.h"

#include "snort.h"

#ifdef GIDS
#include "inline.h"
#endif

#define SNORT_MAGIC     0xa1b2c3d4
#define ALERT_MAGIC     0xDEAD4137  /* alert magic, just accept it */
#define LOG_MAGIC       0xDEAD1080  /* log magic, what's 31337-speak for G? */
#define SNORT_VERSION_MAJOR   1
#define SNORT_VERSION_MINOR   2

/* From fpdetect.c, for logging reassembled packets */
extern u_int32_t   event_id;


/* file header for snort unified format log files
 *
 * Identical to pcap file header, used for portability where the libpcap
 * might not be used after the pa_engine code becomes available
 */ 
typedef struct _UnifiedLogFileHeader
{
    u_int32_t magic;
    u_int16_t version_major;
    u_int16_t version_minor;
    u_int32_t timezone;
    u_int32_t sigfigs;
    u_int32_t snaplen;
    u_int32_t linktype;
} UnifiedLogFileHeader;

typedef struct _UnifiedAlertFileHeader
{
    u_int32_t magic;
    u_int32_t version_major;
    u_int32_t version_minor;
    u_int32_t timezone;
} UnifiedAlertFileHeader;


/* unified log packet header format 
 *
 * One of these per packet in the log file, the packets are appended in the 
 * file after each UnifiedLog header (extended pcap format) 
 */
typedef struct _UnifiedLog
{
    Event event;
    u_int32_t flags;       /* bitmap for interesting flags */
    SnortPktHeader pkth;   /* SnortPktHeader schtuff */
} UnifiedLog;


/* Unified alert message format
 *
 * One per event notification, all the important data for people to know
 */
typedef struct _UnifiedAlert
{
    Event event;
    struct timeval ts;         /* event timestamp */
    u_int32_t sip;             /* src ip */
    u_int32_t dip;             /* dest ip */
    u_int16_t sp;              /* src port */
    u_int16_t dp;              /* dest port */
    u_int32_t protocol;        /* protocol id */
    u_int32_t flags;           /* any other flags (fragmented, etc) */
} UnifiedAlert;



/* ----------------External variables -------------------- */
extern OptTreeNode *otn_tmp;
extern int thiszone;

#ifdef GIDS
#ifndef IPFW
extern ipq_packet_msg_t *g_m;
#endif
#endif

/* ------------------ Data structures --------------------------*/
typedef struct _UnifiedConfig
{
    char *filename;
    FILE *stream;
    unsigned int limit;
    unsigned int current;
} UnifiedConfig;

typedef struct _FileHeader
{
    u_int32_t magic;
    u_int32_t flags;
} FileHeader;

typedef struct _DataHeader
{
    u_int32_t type;
    u_int32_t length;
} DataHeader;

#define UNIFIED_MAGIC 0x2dac5ceb

#define UNIFIED_TYPE_ALERT          0x1
#define UNIFIED_TYPE_PACKET_ALERT   0x2

/* -------------------- Global Variables ----------------------*/
#ifdef GIDS
EtherHdr g_ethernet;
#endif

/* -------------------- Local Functions -----------------------*/
static UnifiedConfig *UnifiedParseArgs(char *, char *);
static void UnifiedCleanExit(int, void *);
static void UnifiedRestart(int, void *);

/* Unified Output functions */
static void UnifiedInit(u_char *);
static void UnifiedInitFile(UnifiedConfig *);
static void UnifiedRotateFile(UnifiedConfig *);
static void UnifiedLogAlert(Packet *, char *, void *, Event *);
static void UnifiedLogPacketAlert(Packet *, char *, void *, Event *);
static void RealUnifiedLogAlert(Packet *, char *, void *, Event *, 
        DataHeader *);
static void RealUnifiedLogPacketAlert(Packet *, char *, void *, Event *, 
        DataHeader *);
void RealUnifiedLogStreamAlert(Packet *,char *,void *,Event *,DataHeader *);
static void UnifiedRotateFile(UnifiedConfig *data);

/* Unified Alert functions (deprecated) */
static void UnifiedAlertInit(u_char *);
static void UnifiedInitAlertFile(UnifiedConfig *);
static void UnifiedAlertRotateFile(UnifiedConfig *data);
static void OldUnifiedLogAlert(Packet *, char *, void *, Event *);


/* Unified Packet Log functions (deprecated) */
static void UnifiedLogInit(u_char *);
static void UnifiedInitLogFile(UnifiedConfig *);
static void OldUnifiedLogPacketAlert(Packet *, char *, void *, Event *);
static void UnifiedLogRotateFile(UnifiedConfig *data);


static UnifiedConfig *unifiedConfig;

/*
 * Function: SetupUnified()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void UnifiedSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("log_unified", NT_OUTPUT_LOG, UnifiedLogInit);
    RegisterOutputPlugin("alert_unified", NT_OUTPUT_ALERT, UnifiedAlertInit);
    RegisterOutputPlugin("unified", NT_OUTPUT_SPECIAL, UnifiedInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: Unified logging/alerting "
			    "is setup...\n"););
}

/*
 * Function: UnifiedInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void UnifiedInit(u_char *args)
{
    if(unifiedConfig)
    {
        FatalError("unified can only be instantiated once\n");
    }

    //DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified Initialized\n"););
    pv.log_plugin_active = 1;
    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    unifiedConfig = UnifiedParseArgs(args, "snort-unified");

    UnifiedInitFile(unifiedConfig);


    //LogMessage("UnifiedFilename = %s\n", unifiedConfig->filename);
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(UnifiedLogAlert, NT_OUTPUT_ALERT, unifiedConfig);
    AddFuncToOutputList(UnifiedLogPacketAlert, NT_OUTPUT_LOG, unifiedConfig);

    AddFuncToCleanExitList(UnifiedCleanExit, unifiedConfig);
    AddFuncToRestartList(UnifiedRestart, unifiedConfig);
}

/*
 * Function: InitOutputFile()
 *
 * Purpose: Initialize the unified ouput file 
 *
 * Arguments: data => pointer to the plugin's reference data struct 
 *
 * Returns: void function
 */
static void UnifiedInitFile(UnifiedConfig *data)
{
    time_t curr_time;      /* place to stick the clock data */
    char logdir[STD_BUF];
    FileHeader hdr;
    int value;

    bzero(logdir, STD_BUF);
    curr_time = time(NULL);

    if(data == NULL)
        FatalError("SpoUnified: Unable to get context data\n");

    if(*(data->filename) == '/')
        value = snprintf(logdir, STD_BUF, "%s.%lu", data->filename, 
                (unsigned long)curr_time);
    else
        value = snprintf(logdir, STD_BUF, "%s/%s.%lu", pv.log_dir,  
                data->filename, (unsigned long)curr_time);

    if(value == -1)
        FatalError("SpoUnified: filepath too long\n");

    //printf("Opening %s\n", logdir);

    if((data->stream = fopen(logdir, "wb")) == NULL)
        FatalError("UnifiedInitLogFile(%s): %s\n", logdir, strerror(errno));

    /* write the log file header */
    hdr.magic = UNIFIED_MAGIC;
    hdr.flags = 0;  /* XXX: not used yet */

    if(fwrite((char *)&hdr, sizeof(hdr), 1, data->stream) != 1)
    {
        FatalError("SpoUnified: InitOutputFile(): %s", strerror(errno));
    }

    fflush(data->stream);

    return;
}

void UnifiedRotateFile(UnifiedConfig *data)
{
    fclose(data->stream);
    data->current = 0;
    UnifiedInitFile(data);
}

int UnifiedLogData(u_int32_t type, u_int32_t length, void *data)
{
    DataHeader dHdr;
    if(!unifiedConfig)
    {
        FatalError("Unified output not configured\n");
    }
    
    /* do not write if data is not available */
    if(!data)
    {
        LogMessage("WARNING: call to LogUnified with NULL data\n");
        return -1;
    }
    /* XXX: length check */
 
    dHdr.type = type;
    dHdr.length = length;
    
    if(fwrite((char *)&dHdr, sizeof(DataHeader), 1, unifiedConfig->stream) 
            != 1)
    {
        FatalError("SpoUnified: write failed: %s\n", strerror(errno));
    }

    if(fwrite((char *)data, length, 1, unifiedConfig->stream) != 1)
    {
        FatalError("SpoUnified: write failed: %s\n", strerror(errno));
    }
    fflush(unifiedConfig->stream);

    return 0;
}

void UnifiedLogAlert(Packet *p, char *msg, void *arg, Event *event)
{
    DataHeader dHdr;
    dHdr.type = UNIFIED_TYPE_ALERT;
    dHdr.length = sizeof(UnifiedAlert);
    
    /* check for a pseudo-packet, we don't want to log those */
    RealUnifiedLogAlert(p, msg, arg, event, &dHdr);
}
    
void RealUnifiedLogAlert(Packet *p, char *msg, void *arg, Event *event, 
        DataHeader *dHdr)
{
    UnifiedConfig *data = (UnifiedConfig *)arg;
    UnifiedAlert alertdata;

    bzero(&alertdata, sizeof(alertdata));

    if(event != NULL)
    {
        alertdata.event.sig_generator = event->sig_generator;
        alertdata.event.sig_id = event->sig_id;
        alertdata.event.sig_rev = event->sig_rev;
        alertdata.event.classification = event->classification;
        alertdata.event.priority = event->priority;
        alertdata.event.event_id = event->event_id;
        alertdata.event.event_reference = event->event_reference;
        alertdata.event.ref_time.tv_sec = event->ref_time.tv_sec;
        alertdata.event.ref_time.tv_usec = event->ref_time.tv_usec;

    }

    if(p)
    {
        alertdata.ts.tv_sec = p->pkth->ts.tv_sec;
        alertdata.ts.tv_usec = p->pkth->ts.tv_usec;

        if(p->iph != NULL)
        {
            /* everything needs to be written in host order */
            alertdata.sip = ntohl(p->iph->ip_src.s_addr);
            alertdata.dip = ntohl(p->iph->ip_dst.s_addr);
            if(p->iph->ip_proto == IPPROTO_ICMP)
            {
                if(p->icmph != NULL)
                {
                    alertdata.sp = p->icmph->type;
                    alertdata.dp = p->icmph->code;
                }
            }
            else
            {
                alertdata.sp = p->sp;
                alertdata.dp = p->dp;
            }
            alertdata.protocol = p->iph->ip_proto;
            alertdata.flags = p->packet_flags;
        }
    }
    
    /* backward compatibility stuff */
    if(dHdr == NULL)
    {
        if((data->current + sizeof(UnifiedAlert)) > data->limit)
            UnifiedAlertRotateFile(data);
    }
    else
    {
        if((data->current + sizeof(UnifiedAlert)) > data->limit)
            UnifiedRotateFile(data);
    }

    if(dHdr)
    {
        if(fwrite((char *)dHdr, sizeof(DataHeader), 1, data->stream) != 1)
            FatalError("SpoUnified: write failed: %s\n", strerror(errno));
        data->current += sizeof(DataHeader);
    }
    
    if(fwrite((char *)&alertdata, sizeof(UnifiedAlert), 1, data->stream) != 1)
            FatalError("SpoUnified: write failed: %s\n", strerror(errno));


    fflush(data->stream);
    data->current += sizeof(UnifiedAlert);
}


void UnifiedLogPacketAlert(Packet *p, char *msg, void *arg, Event *event)
{
    DataHeader dHdr;
    dHdr.type = UNIFIED_TYPE_PACKET_ALERT;
    dHdr.length = sizeof(UnifiedLog);
    
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, 
                    "[*] Reassembled packet, dumping stream packets\n"););
        RealUnifiedLogStreamAlert(p, msg, arg, event, &dHdr);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "[*] Logging unified packets...\n"););
        RealUnifiedLogPacketAlert(p, msg, arg, event, &dHdr);
    }

}


void RealUnifiedLogPacketAlert(Packet *p, char *msg, void *arg, Event *event,
        DataHeader *dHdr)
{
    UnifiedLog logheader;
    UnifiedConfig *data = (UnifiedConfig *)arg;

    if(event != NULL)
    {
        logheader.event.sig_generator = event->sig_generator;
        logheader.event.sig_id = event->sig_id;
        logheader.event.sig_rev = event->sig_rev;
        logheader.event.classification = event->classification;
        logheader.event.priority = event->priority;
        logheader.event.event_id = event->event_id;
        logheader.event.event_reference = event->event_reference;
        logheader.event.ref_time.tv_sec = event->ref_time.tv_sec;
        logheader.event.ref_time.tv_usec = event->ref_time.tv_usec;

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "------------\n");
		   DebugMessage(DEBUG_LOG, "gen: %u\n", logheader.event.sig_generator);
		   DebugMessage(DEBUG_LOG, "sid: %u\n", logheader.event.sig_id);
		   DebugMessage(DEBUG_LOG, "rev: %u\n", logheader.event.sig_rev);
		   DebugMessage(DEBUG_LOG, "cls: %u\n", logheader.event.classification);
		   DebugMessage(DEBUG_LOG, "pri: %u\n", logheader.event.priority);
		   DebugMessage(DEBUG_LOG, "eid: %u\n", logheader.event.event_id);
		   DebugMessage(DEBUG_LOG, "erf: %u\n", logheader.event.event_reference);
		   DebugMessage(DEBUG_LOG, "sec: %lu\n", logheader.event.ref_time.tv_sec);
		   DebugMessage(DEBUG_LOG, "usc: %lu\n", logheader.event.ref_time.tv_usec););
    }

    if(p)
    {
        logheader.flags = p->packet_flags;

        /* 
         * this will have to be fixed when we transition to the pa_engine
         * code (p->pkth is libpcap specific)
         */ 
        memcpy(&logheader.pkth, p->pkth, sizeof(SnortPktHeader));
    }
    else
    {
        logheader.flags = 0;
        logheader.pkth.ts.tv_sec = 0;
        logheader.pkth.ts.tv_usec = 0;
        logheader.pkth.caplen = 0;
        logheader.pkth.pktlen = 0;
    }
    
    /* backward compatibility stuff */
    if(dHdr == NULL)
    {
        if((data->current + sizeof(UnifiedLog) + logheader.pkth.caplen) > 
                data->limit)
            UnifiedLogRotateFile(data);
    }
    else
    {   
        if((data->current + sizeof(UnifiedLog) + sizeof(DataHeader) 
                    + logheader.pkth.caplen) > data->limit)
            UnifiedRotateFile(data);
    }
    if(dHdr)
    {
        if(fwrite((char *)dHdr, sizeof(DataHeader), 1, data->stream) != 1)
            FatalError("SpoUnified: write failed: %s\n", strerror(errno));
        data->current += sizeof(DataHeader);
    }
        
    
    if(fwrite((char*)&logheader, sizeof(UnifiedLog), 1, data->stream) != 1)
        FatalError("SpoUnified: write failed: %s\n", strerror(errno));
    data->current += sizeof(UnifiedLog);
    
    if(p)
    {
        if(fwrite((char*)p->pkt, p->pkth->caplen, 1, data->stream) != 1)
            FatalError("SpoUnified: write failed: %s\n", strerror(errno));
        data->current += p->pkth->caplen;
    }

    fflush(data->stream);
}



/**
 * Log a set of packets stored in the stream reassembler
 *
 */
void RealUnifiedLogStreamAlert(Packet *p, char *msg, void *arg, Event *event,
        DataHeader *dHdr)
{
    Stream *s = NULL;
    StreamPacketData *spd;
    UnifiedLog logheader;
    UnifiedConfig *data = (UnifiedConfig *)arg;
    int once = 0;

    /* setup the event header */
    if(event != NULL)
    {
        logheader.event.sig_generator = event->sig_generator;
        logheader.event.sig_id = event->sig_id;
        logheader.event.sig_rev = event->sig_rev;
        logheader.event.classification = event->classification;
        logheader.event.priority = event->priority;
        logheader.event.event_id = event->event_id;
        logheader.event.event_reference = event->event_reference;
        /* Note that ref_time is probably incorrect.  
         * See OldUnifiedLogPacketAlert() for details. */
        logheader.event.ref_time.tv_sec = event->ref_time.tv_sec;
        logheader.event.ref_time.tv_usec = event->ref_time.tv_usec;

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "------------\n");
		   DebugMessage(DEBUG_LOG, "gen: %u\n", logheader.event.sig_generator);
		   DebugMessage(DEBUG_LOG, "sid: %u\n", logheader.event.sig_id);
		   DebugMessage(DEBUG_LOG, "rev: %u\n", logheader.event.sig_rev);
		   DebugMessage(DEBUG_LOG, "cls: %u\n", logheader.event.classification);
		   DebugMessage(DEBUG_LOG, "pri: %u\n", logheader.event.priority);
		   DebugMessage(DEBUG_LOG, "eid: %u\n", logheader.event.event_id);
		   DebugMessage(DEBUG_LOG, "erf: %u\n", 
               logheader.event.event_reference);
		   DebugMessage(DEBUG_LOG, "sec: %lu\n", 
               logheader.event.ref_time.tv_sec);
		   DebugMessage(DEBUG_LOG, "usc: %lu\n", 
               logheader.event.ref_time.tv_usec););
    }

    /* queue up the stream for logging */
    if(p)
    {
        s = (Stream *) p->streamptr;

        /* get the first segment... */
        spd = (StreamPacketData *) ubi_btFirst((ubi_btNodePtr)&s->data);

        /* loop thru all the packets in the stream */
        do
        {
            /* packets that are part of the currently reassembled stream
             * should be marked with the chuck flag
             */
            if(spd->chuck != SEG_UNASSEMBLED)
            {
                /* copy it's pktheader data into the logheader */
                memcpy(&logheader.pkth, &spd->pkth, sizeof(SnortPktHeader));

                /* backward compatibility stuff */
                if(dHdr == NULL)
                {
                    if((data->current +
                        sizeof(UnifiedLog)+
                        logheader.pkth.caplen) > 
                        data->limit)
                    {
                        UnifiedLogRotateFile(data);
                    }
                }
                else
                {   
                    if((data->current + sizeof(UnifiedLog) + sizeof(DataHeader) 
                                + logheader.pkth.caplen) > data->limit)
                        UnifiedRotateFile(data);
                }

                if(dHdr)
                {
                    if(fwrite((char*)dHdr,sizeof(DataHeader),1,data->stream) 
                            != 1)
                        FatalError("SpoUnified: write failed: %s\n", 
                                strerror(errno));
                    data->current += sizeof(DataHeader);
                }

                if(fwrite((char*)&logheader,sizeof(UnifiedLog),1,data->stream)
                       != 1)
                    FatalError("SpoUnified: write failed: %s\n", 
                            strerror(errno));

                data->current += sizeof(UnifiedLog);

                if(spd->pkt)
                {
                    if(fwrite((char*)spd->pkt,logheader.pkth.caplen,1
                                ,data->stream) != 1)
                        FatalError("SpoUnified: write failed: %s\n", 
                                strerror(errno));

                    data->current += logheader.pkth.caplen;
                }

                /* after the first logged packet modify the event headers */
                if(!once++)
                {
                    logheader.event.sig_generator = GENERATOR_TAG;
                    logheader.event.sig_id = TAG_LOG_PKT;
                    logheader.event.sig_rev = 1;
                    logheader.event.classification = 0;
                    logheader.event.priority = event->priority;
                    /* Note that event_id is now incorrect. 
                     * See OldUnifiedLogPacketAlert() for details. */
                }
            }

        } while((spd=(StreamPacketData*)ubi_btNext((ubi_btNodePtr)spd))
                !=NULL);
    }
    
    fflush(data->stream);
}
    
/*
 * Function: UnifiedParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
UnifiedConfig *UnifiedParseArgs(char *args, char *default_filename)
{
    UnifiedConfig *tmp;
    int limit = 0;

    tmp = (UnifiedConfig *)calloc(sizeof(UnifiedConfig), sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate Unified Data struct!\n");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Args: %s\n", args););

    if(args != NULL)
    {
        char **toks;
        int num_toks;
        int i = 0;
        toks = mSplit(args, ",", 31, &num_toks, '\\');
        for(i = 0; i < num_toks; ++i)
        {
            char **stoks;
            int num_stoks;
            char *index = toks[i];
            while(isspace((int)*index))
                ++index;
          
            stoks = mSplit(index, " ", 2, &num_stoks, 0);
            
            if(strcasecmp("filename", stoks[0]) == 0)
            {
                if(num_stoks > 1 && tmp->filename == NULL)
                    tmp->filename = strdup(stoks[1]);
                else
                    LogMessage("Argument Error in %s(%i): %s\n",
                            file_name, file_line, index);
            }
            if(strcasecmp("limit", stoks[0]) == 0)
            {
                if(num_stoks > 1 && limit == 0)
                {
                    limit = atoi(stoks[1]);
                }
                else
                {
                    LogMessage("Argument Error in %s(%i): %s\n",
                            file_name, file_line, index);
                }
            }
            do
                free(stoks[--num_stoks]);
            while(num_stoks);
        }
        do
            free(toks[--num_toks]);
        while(num_toks);
    }

    if(tmp->filename == NULL)
        tmp->filename = strdup(default_filename);
    
    //LogMessage("limit == %i\n", limit);

    if(limit <= 0)
    {
        limit = 128;
    }
    if(limit > 512)
    {
        LogMessage("spo_unified %s(%d)=> Lowering limit of %iMB to 512MB\n", file_name, file_line, limit);
        limit = 512;
    }

    /* convert the limit to "MB" */
    tmp->limit = limit << 20;

    return tmp;
}


/*
 * Function: UnifiedCleanExitFunc()
 *
 * Purpose: Cleanup at exit time
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void UnifiedCleanExit(int signal, void *arg)
{
    /* cast the arg pointer to the proper type */
    UnifiedConfig *data = (UnifiedConfig *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "SpoUnified: CleanExit\n"););

    fclose(data->stream);

    /* free up initialized memory */
    free(data->filename);
    free(data);
}



/*
 * Function: Restart()
 *
 * Purpose: For restarts (SIGHUP usually) clean up structs that need it
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void UnifiedRestart(int signal, void *arg)
{
    UnifiedConfig *data = (UnifiedConfig *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "SpoUnified: Restart\n"););

    fclose(data->stream);
    free(data->filename);
    free(data);
}



/* Unified Alert functions (deprecated) */
void UnifiedAlertInit(u_char *args)
{
    UnifiedConfig *data;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified Alert Initialized\n"););

    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = UnifiedParseArgs(args, "snort-unified.alert");

    UnifiedInitAlertFile(data);


    //LogMessage("UnifiedAlertFilename = %s\n", data->filename);
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(OldUnifiedLogAlert, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(UnifiedCleanExit, data);
    AddFuncToRestartList(UnifiedRestart, data);
}
/*
 * Function: UnifiedInitAlertFile()
 *
 * Purpose: Initialize the unified log alert file
 *
 * Arguments: data => pointer to the plugin's reference data struct 
 *
 * Returns: void function
 */
void UnifiedInitAlertFile(UnifiedConfig *data)
{
    time_t curr_time;      /* place to stick the clock data */
    char logdir[STD_BUF];
    int value;
    UnifiedAlertFileHeader hdr;

    bzero(logdir, STD_BUF);
    curr_time = time(NULL);

    if(data->filename[0] == '/')
        value = snprintf(logdir, STD_BUF, "%s.%lu",  data->filename, 
                (unsigned long)curr_time);
    else
        value = snprintf(logdir, STD_BUF, "%s/%s.%lu", pv.log_dir, 
                data->filename, (unsigned long)curr_time);

    if(value == -1)
    {
        FatalError("unified log file logging path and file name are "
                   "too long, aborting!\n");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "Opening %s\n", logdir););

    if((data->stream = fopen(logdir, "wb+")) == NULL)
    {
        FatalError("UnifiedInitAlertFile(%s): %s\n", logdir, strerror(errno));
    }

    hdr.magic = ALERT_MAGIC;
    hdr.version_major = 1;
    hdr.version_minor = 81;
    hdr.timezone = thiszone;

    if(fwrite((char *)&hdr, sizeof(hdr), 1, data->stream) != 1)
    {
        FatalError("UnifiedAlertInit(): %s\n", strerror(errno));
    }
        
    fflush(data->stream);

    return;
}


void OldUnifiedLogAlert(Packet *p, char *msg, void *arg, Event *event)
{
    RealUnifiedLogAlert(p, msg, arg, event, NULL);
}

void UnifiedAlertRotateFile(UnifiedConfig *data)
{

    fclose(data->stream);
    data->current = 0;
    UnifiedInitAlertFile(data);
}

/* Unified Packet Log functions (deprecated) */

void UnifiedLogInit(u_char *args)
{
    UnifiedConfig *UnifiedInfo;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified Log Initialized\n"););

    /* tell command line loggers to go away */
    pv.log_plugin_active = 1;

    /* parse the argument list from the rules file */
    UnifiedInfo = UnifiedParseArgs(args, "snort-unified.log");

    //LogMessage("UnifiedLogFilename = %s\n", UnifiedInfo->filename);

    UnifiedInitLogFile(UnifiedInfo);

    pv.log_bitmap |= LOG_UNIFIED;

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(OldUnifiedLogPacketAlert, NT_OUTPUT_LOG, UnifiedInfo);
    AddFuncToCleanExitList(UnifiedCleanExit, UnifiedInfo);
    AddFuncToRestartList(UnifiedRestart, UnifiedInfo);
}


/*
 * Function: UnifiedInitLogFile()
 *
 * Purpose: Initialize the unified log file header
 *
 * Arguments: data => pointer to the plugin's reference data struct 
 *
 * Returns: void function
 */
void UnifiedInitLogFile(UnifiedConfig *data)
{
    time_t curr_time;      /* place to stick the clock data */
    char logdir[STD_BUF];
    int value;
    UnifiedLogFileHeader hdr;

    bzero(logdir, STD_BUF);
    curr_time = time(NULL);

    if(data == NULL)
    {
        FatalError("Can't get unified plugin context, that's bad\n");
    }

    if(*(data->filename) == '/')
        value = snprintf(logdir, STD_BUF, "%s.%lu", data->filename, 
                (unsigned long)curr_time);
    else
        value = snprintf(logdir, STD_BUF, "%s/%s.%lu", pv.log_dir,  
                data->filename, (unsigned long)curr_time);

    if(value == -1)
    {
        FatalError("unified log file logging path and file name are "
                   "too long, aborting!\n");
    }

    if((data->stream = fopen(logdir, "wb")) == NULL)
    {
        FatalError("UnifiedInitLogFile(%s): %s\n", logdir, strerror(errno));
    }

    /* write the log file header */
    hdr.magic = LOG_MAGIC;
    hdr.version_major = SNORT_VERSION_MAJOR;
    hdr.version_minor = SNORT_VERSION_MINOR;
    hdr.timezone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = datalink;

#ifdef GIDS
    hdr.linktype = DLT_EN10MB;
#endif

    if(fwrite((char *)&hdr, sizeof(hdr), 1, data->stream) != 1)
    {
        FatalError("UnifiedLogInit(): %s", strerror(errno));
    }

    fflush(data->stream);

    return;
}

/*
 * Function: LogUnified(Packet *, char *msg, void *arg)
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
void OldUnifiedLogPacketAlert(Packet *p, char *msg, void *arg, Event *event)
{
    Stream *s = NULL;
    StreamPacketData *spd = NULL;
    int first_time = 1;
    UnifiedLog logheader;
    UnifiedConfig *data = (UnifiedConfig *)arg;

    if(event != NULL)
    {
        logheader.event.sig_generator = event->sig_generator;
        logheader.event.sig_id = event->sig_id;
        logheader.event.sig_rev = event->sig_rev;
        logheader.event.classification = event->classification;
        logheader.event.priority = event->priority;
        logheader.event.event_id = event->event_id;
        logheader.event.event_reference = event->event_reference;

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "------------\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "gen: %u\n", 
                    logheader.event.sig_generator););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "sid: %u\n", 
                    logheader.event.sig_id););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "rev: %u\n", 
                    logheader.event.sig_rev););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "cls: %u\n", 
                    logheader.event.classification););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "pri: %u\n", 
                    logheader.event.priority););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "eid: %u\n", 
                    logheader.event.event_id););
        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "erf: %u\n", 
                    logheader.event.event_reference););
    }

    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        s = (Stream *) p->streamptr;

        /* get the first segment... */
        spd = (StreamPacketData *) ubi_btFirst((ubi_btNodePtr)&s->data);

        /* loop thru all the packets in the stream */
        while (spd != NULL )
        {
            /* packets that are part of the currently reassembled stream
             * should be marked with the chuck flag
             */
            if(spd->chuck != SEG_UNASSEMBLED)
            {
                logheader.flags = p->packet_flags;

                /* copy it's pktheader data into the logheader */
                memcpy(&logheader.pkth, &spd->pkth, sizeof(SnortPktHeader));

#ifdef GIDS
                /*
                **  Add the ethernet header size to the total pktlen.
                **  If the ethernet hdr is already set, then this means
                **  that it's a portscan packet and we don't add the
                **  ethernet header.
                */
                if(!p->eh)
                {
                    logheader.pkth.caplen += sizeof(EtherHdr);
                    logheader.pkth.pktlen += sizeof(EtherHdr);
                }
#endif

               /*  Set reference time equal to log time for the first packet  */
                if (first_time)
                {                    
                    logheader.event.ref_time.tv_sec = logheader.pkth.ts.tv_sec;
                    logheader.event.ref_time.tv_usec = logheader.pkth.ts.tv_usec;
                    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "sec: %lu\n", 
                                logheader.event.ref_time.tv_sec););
                    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "usc: %lu\n", 
                                logheader.event.ref_time.tv_usec););

                }

                if(fwrite((char*)&logheader,sizeof(UnifiedLog),1,data->stream)
                       != 1)
                    FatalError("SpoUnified: write failed: %s\n", 
                            strerror(errno));

                data->current += sizeof(UnifiedLog);

                if(spd->pkt)
                {
#ifdef GIDS
                    if(!p->eh)
                    {
#ifndef IPFW
                        memcpy((u_char *)g_ethernet.ether_src,g_m->hw_addr,6);
                        memset((u_char *)g_ethernet.ether_dst,0x00,6);
#else
                        memset(g_ethernet.ether_dst,0x00,6);
                        memset(g_ethernet.ether_src,0x00,6);
#endif
                        g_ethernet.ether_type = htons(0x0800);

                        if(fwrite((char*)&g_ethernet,sizeof(EtherHdr),1,data->stream) != 1)
                            FatalError("SpoUnified: write failed: %s\n", strerror(errno));
                        data->current += sizeof(EtherHdr);
                    }
#endif
        
                    if(fwrite((char*)spd->pkt,spd->pkth.caplen,1
                                ,data->stream) != 1)
                        FatalError("SpoUnified: write failed: %s\n", 
                                strerror(errno));

                    data->current += spd->pkth.caplen;
                }

                /* after the first logged packet modify the event headers */
                if (first_time)
                {                    
                    logheader.event.sig_generator = GENERATOR_TAG;
                    logheader.event.sig_id = TAG_LOG_PKT;
                    logheader.event.sig_rev = 1;
                    logheader.event.classification = 0;
                    logheader.event.priority = event->priority;    
                    first_time = 0;
                }

                /* Update event ID for subsequent logged packets */
                logheader.event.event_id = ++event_id;                
            }

            spd = (StreamPacketData*) ubi_btNext((ubi_btNodePtr)spd);
        }
    }
    else
    {
        if(p)
        {
            logheader.flags = p->packet_flags;

            memcpy(&logheader.pkth, p->pkth, sizeof(SnortPktHeader));

#ifdef GIDS
            /*
            **  Add the ethernet header size to the total pktlen.
            **  If the ethernet hdr is already set, then this means
            **  that it's a portscan packet and we don't add the
            **  ethernet header.
            */
            if(!p->eh)
            {
                logheader.pkth.caplen += sizeof(EtherHdr);
                logheader.pkth.pktlen += sizeof(EtherHdr);
            }
#endif
        }
        else
        {
            logheader.flags = 0;
            logheader.pkth.ts.tv_sec = 0;
            logheader.pkth.ts.tv_usec = 0;
            logheader.pkth.caplen = 0;
            logheader.pkth.pktlen = 0;
        }

        if((data->current + sizeof(UnifiedLog) + logheader.pkth.caplen) > 
                data->limit)
            UnifiedLogRotateFile(data);

        fwrite((char*)&logheader, sizeof(UnifiedLog), 1, data->stream);

        if(p)
        {
#ifdef GIDS
            if(!p->eh)
            {
#ifndef IPFW
                memcpy((u_char *)g_ethernet.ether_src,g_m->hw_addr,6);
                memset((u_char *)g_ethernet.ether_dst,0x00,6);
#else
                memset(g_ethernet.ether_dst,0x00,6);
                memset(g_ethernet.ether_src,0x00,6);
#endif
                g_ethernet.ether_type = htons(0x0800);

                if(fwrite((char*)&g_ethernet,sizeof(EtherHdr),1,data->stream) != 1)
                    FatalError("SpoUnified: write failed: %s\n", strerror(errno));
                data->current += sizeof(EtherHdr);
            }
#endif
        
            fwrite((char*)p->pkt, p->pkth->caplen, 1, data->stream);
        }
    }

    fflush(data->stream);

    data->current += sizeof(UnifiedLog) + p->pkth->caplen;
    
}


void UnifiedLogRotateFile(UnifiedConfig *data)
{

    fclose(data->stream);
    data->current = 0;
    UnifiedInitLogFile(data);
}

