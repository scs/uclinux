/* $Id$ */
/*
** Copyright (C) 1998,1999,2000,2001 Martin Roesch <roesch@clark.net>
** Copyright (C) 2001 Jed Haile  <jhaile@nitrodata.com>
** Copyright (C) 2002 Sourcefire, Inc
**                    Chris Green <cmg@sourcefire.com>
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

/* state based portscan detector
 *  by Jed Haile <jhaile@nitrodata.com>
 *  version 0.0.1
 *  todo:  1. track timestamp, src, dst, proto, sport/icode,
 *		dport/itype, length
 */

/* ChangeLog:
 * * Fri Nov 22 2002 Joerg Lehrke <jlehrke@noc.de>
 * - fixed ignorehosts
 * * Tue Nov 26 2002 Joerg Lehrke <jlehrke@noc.de>
 * - added ignoreports
 * * Thu Nov 28 2002 Joerg Lehrke <jlehrke@noc.de>
 * - added port restriction to ignorehosts
 * * Tue Dec  3 2002 Joerg Lehrke <jlehrke@noc.de>
 * - fixed precedence problems
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define MODNAME "spp_portscan2"
#define MAX_TARGETS 5
#define MAX_PORTS 64
#define MEM_CHUNK 32
#define PS_T 1
#define TGT_T 2

#ifndef TRUE
#define TRUE 0
#endif
#ifndef FALSE
#define FALSE 1
#endif

#define OPT_TARGET_COUNT "targets_max"
#define OPT_MAX_SCANNER "scanners_max"
#define OPT_TGT_LIMIT "target_limit"
#define OPT_PORT_LIMIT "port_limit"
#define OPT_TIMEOUT "timeout"
#define OPT_LOG "log"

#define DEFAULT_MAX_SCANNER 1000
#define DEFAULT_TARGET_COUNT 1000
#define DEFAULT_TARGET_LIMIT 5
#define DEFAULT_PORT_LIMIT   20
#define DEFAULT_TIMEOUT      60




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

#include "spp_portscan2.h"
#include "spp_conversation.h"
#include "mempool.h"
#include "plugbase.h"
#include "mstring.h"
#include "util.h"
#include "log.h"
#include "parser.h"
#include "detect.h"
#include "rules.h"
#include "decode.h"
#include "debug.h"
#include "ubi_SplayTree.h"
#include "ubi_BinTree.h"
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */
#include "generators.h"

#include <assert.h>

/* this represents the incoming host */
typedef struct _PortScanner
{
    ubi_trNode Node;             /* for the splay tree */
    MemBucket *bucket;

    u_int32_t scanner_ip;

    struct timeval initial_time;
    struct timeval last_time;

    int port_count;     /* total count of ports this scanner has hit */
    int target_count;  /* total count of targets this scanner has hit */
    
    ubi_trRoot targetRoot;  /* this scanner's target tree*/
    ubi_trRootPtr targetRootPtr; 

    int targetsExceeded;
    int portsExceeded;

    int bytes;     /* counts of things that happended */
    int packets;
    
    u_int32_t event_id;    
} Portscanner;

typedef struct _ScanTarget
{
    ubi_trNode Node;
    Portscanner *parent;  /*pointer to the parent Portscanner node */
    MemBucket *bucket;

    
    u_int32_t target_ip;
    int port_count;   /* number of ports on this target hit by parent portscanner*/

    struct timeval initial_time;
    struct timeval last_time;

    char plist[65536/8];  /* an array of bytes to store port info */
} ScanTarget;

typedef struct _hostNode
{
    IpAddrSet *address;
    u_short hsp;         /* hi src port */
    u_short lsp;         /* lo src port */
    u_int32_t flags;     /* control flags */
    struct _hostNode *nextNode;
} HostNode;

HostNode *ignoreList; /* for ignore-hosts */

/* ignore-ports-from, ignore-ports-to */
int num_ports_from;
int num_ports_to;
u_int32_t *ignorePortFrom;
u_int32_t *ignorePortTo;

typedef struct _Portscan2Data
{
    ubi_trRoot Scanners;

    ubi_trRootPtr ScannersPtr;

    u_int32_t scanner_count;
    u_int32_t target_count;
    
    MemPool TargetPool;
    MemPool ScannerPool;

    /** Global Program Data **/
    FILE *logfile;
    char *logpath;

    int tgtThreshold;   /* number of distinc targets to allow */
    int portThreshold;  /* number of distinct ports to allow before alerting */
    int timeout;
    char isInitialized;
    struct timeval prune_time;
} Portscan2Data;


Portscan2Data ps2data;

/** external globals from rules.c **/
extern char *file_name;
extern int file_line;
extern u_int32_t event_id;


/** FUNCTION PROTOTYPES **/
void Scan2Init(u_char *);
static int targetCompareFunc(ubi_trItemPtr , ubi_trNodePtr);

/* void AddTarget(ubi_trRootPtr, u_int32_t, u_int16_t, u_int32_t); */
void ParseScanmungeArgs(u_char *);
/* delete the nodes from a portscanner */
static int PruneTargets(Portscanner *p, u_int32_t now, int tokill);
static int PrunePortscanners(u_int32_t now, int tokill, Portscanner *saveme);

void SLog(Packet *, int, Portscanner *);
void SAlert(Packet *, int, Portscanner *);
INLINE int portIsSet(char *, int);
INLINE void InitPortlist(ScanTarget *target);
void setPort(char *, int);
void dumpPacketStats(Portscanner *);

/* For ignore hosts */
void InitIgnoreHosts(u_char *);
IpAddrSet* IgnoreAllocAddrNode(HostNode *);
void ScanParseIp(char *, HostNode *);

/* For ignore ports */
void InitIgnoreFrom(u_char *);
void InitIgnoreTo(u_char *);
void InitIgnorePorts(u_char *, u_int32_t **, int *);
u_int32_t ScanParsePort(char *);

int IsIgnored(Packet *);

/*************************************************************/
/* Parses all of scan2's args. They are as follows:          */
/* int psnodes, int targetnodes, char log, int targets,      */
/* int ports, int timeout                                    */
/*************************************************************/
void ParseScanmungeArgs(u_char *args)
{
    int num_toks, s_toks;
    char **toks = NULL;
    char **stoks;
    int i;
    char* index;
    char logpath[STD_BUF], tmp[STD_BUF];

    /* setup the defaults */
    strncpy(logpath, pv.log_dir, STD_BUF);
    strncpy(tmp, "/scan.log", STD_BUF);
    strncat(logpath, tmp, STD_BUF);

    /* way too low of defaults */
    ps2data.scanner_count = DEFAULT_MAX_SCANNER;
    ps2data.target_count  = DEFAULT_TARGET_COUNT;
    ps2data.tgtThreshold  = DEFAULT_TARGET_LIMIT;
    ps2data.portThreshold = DEFAULT_PORT_LIMIT;
    ps2data.timeout       = DEFAULT_TIMEOUT;

    if (args)
    {

        toks = mSplit(args, ",", 11, &num_toks, 0);

        i=0;

        while (i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 4, &s_toks, 0);

            if (!stoks[1] || stoks[1][0] == '\0')
            {
                FatalError("%s: %s(%d) => '%s' has null value. ",
                           MODNAME, file_name, file_line, stoks[0]);
            }
            if(!strcasecmp(stoks[0], OPT_MAX_SCANNER))
            {
                if(isdigit((int)stoks[1][0]))
                {
                    /* number of psnodes */
                    ps2data.scanner_count = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    /* lets cool it with the leeway */
                    FatalError("%s: %s(%d) => '%s' has invalid value '%s'. ",
                               MODNAME, file_name, file_line,
			       stoks[0], stoks[1]);
                }
            }
            else if(!strcasecmp(stoks[0], OPT_TARGET_COUNT))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /* number of tgtnodes */
                    ps2data.target_count = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("%s: %s(%d) => '%s' has invalid value '%s'. ",
                               MODNAME, file_name, file_line,
			       stoks[0], stoks[1]);
                }
            }
            else if(!strcasecmp(stoks[0], OPT_TGT_LIMIT))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /* number of targets */
                    ps2data.tgtThreshold = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("%s: %s(%d) => '%s' has invalid value '%s'. ",
                               MODNAME, file_name, file_line,
			       stoks[0], stoks[1]);
                }
            }
            else if(!strcasecmp(stoks[0], OPT_PORT_LIMIT))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /*  number of ports */
                    ps2data.portThreshold = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("%s: %s(%d) => '%s' has invalid value '%s'. ",
                               MODNAME, file_name, file_line,
			       stoks[0], stoks[1]);
                }
            }
            else if(!strcasecmp(stoks[0], OPT_TIMEOUT))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    ps2data.timeout = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("%s: %s(%d) => '%s' has invalid value '%s'. ",
                               MODNAME, file_name, file_line,
			       stoks[0], stoks[1]);
                }
            }
            else if(!strcasecmp(stoks[0], OPT_LOG))
            {
                if(isascii((int)(stoks[1][0])))
                {
                    if (stoks[1][0] == '/')
                        strncpy (logpath, stoks[1], STD_BUF);
                    else
                    {
                        strncpy(logpath, pv.log_dir, STD_BUF);
                        strncat(logpath, "/", STD_BUF);
                        strncat(logpath, stoks[1], STD_BUF);
                    }
                    i++;
                }
                else
                {
                    FatalError("%s: %s(%d) => '%s' has invalid value '%s'. ",
                               MODNAME, file_name, file_line,
			       stoks[0], stoks[1]);
                }
            }
            else
            {
                FatalError("%s: %s(%d) => option '%s' is undefined. ",
                           MODNAME, file_name, file_line, stoks[0]);
            }

            mSplitFree(&stoks, s_toks);
        }
        mSplitFree(&toks, num_toks);
    }           
    LogMessage ("    %s: %s\n", OPT_LOG, logpath);
    LogMessage ("    %s: %d\n", OPT_MAX_SCANNER, ps2data.scanner_count);
    LogMessage ("    %s: %d\n", OPT_TARGET_COUNT, ps2data.target_count);
    LogMessage ("    %s: %d\n", OPT_TGT_LIMIT, ps2data.tgtThreshold);
    LogMessage ("    %s: %d\n", OPT_PORT_LIMIT, ps2data.portThreshold);
    LogMessage ("    %s: %d\n", OPT_TIMEOUT, ps2data.timeout);


    ps2data.logfile = fopen(logpath, "a+");

    if(ps2data.logfile == NULL)
    {
        FatalError("Can't open logfile: %s", ps2data.logpath);
    }
}

/*************************************************************/
/* Called at runtime to establish the list of hosts who are  */
/* to be ignored by the portscan detector                    */
/*************************************************************/
void InitIgnoreHosts(u_char *hosts)
{
    char **toks;
    int num_toks;
    int num_hosts = 0;
    HostNode *currentHost;
    /*int i;*/

#ifdef DEBUG
    char ruleIP[16], ruleNetMask[16];
#endif

    currentHost = NULL;
    ignoreList = NULL;
        
    if(hosts == NULL)
    {
        ErrorMessage(MODNAME ": ERROR: %s(%d)=> No arguments to "
                     "portscan2-ignorehosts, ignoring.\n",
		     file_name, file_line);
        return;
    }

    toks = mSplit(hosts, " ", 127, &num_toks, '\\');
        
    for(num_hosts = 0; num_hosts < num_toks; num_hosts++)
    {
        if((currentHost = (HostNode *) calloc(1, sizeof(HostNode))) == NULL)
	{
	    FatalError("[!] ERROR: Unable to allocate space for "
		       "portscan IgnoreHost");
	} 
	currentHost->address = NULL; /* be paranoid */
	currentHost->nextNode = ignoreList;
	ignoreList = currentHost;

#ifdef DEBUG
	printf(MODNAME ": InitIgnoreHosts(): Adding server %s\n", 
	       toks[num_hosts]);
#endif  /* DEBUG */

	ScanParseIp(toks[num_hosts], currentHost);
    }

    mSplitFree(&toks, num_toks);
    
#ifdef DEBUG
    currentHost = ignoreList;
   
    while(currentHost)
    {
	memset(ruleIP, '\0', 16);
        memset(ruleNetMask, '\0', 16);

        strncpy(ruleIP, 
                inet_ntoa(*(struct in_addr *) & currentHost->address->ip_addr),
                15);
        strncpy(ruleNetMask, 
                inet_ntoa(*(struct in_addr *) & currentHost->address->netmask),
                15);

        printf(MODNAME ": InitIgnoreHosts(): Added server %s/%s\n", 
               ruleIP, ruleNetMask);
	currentHost = currentHost->nextNode;
    }
#endif  /* DEBUG */

}

/************************************************************/
/* Helper function to set up the list of ignored hosts      */
/************************************************************/
IpAddrSet* IgnoreAllocAddrNode(HostNode *host)
{
    IpAddrSet *idx;

    if((idx = (IpAddrSet *) calloc(1, sizeof(IpAddrSet))) == NULL)
      {
        FatalError("[!] ERROR: Unable to allocate space for "
                       "portscan IP addr\n");
      }

    idx->next = host->address;
    host->address = idx;

    return idx;
}

/*******************************************************************/
/* parses the IP's in the ignore hosts list                        */
/*******************************************************************/
void ScanParseIp(char *addr, HostNode *host)
{
    char **toks;
    int num_toks;
    int i, not_flag;
    IpAddrSet *tmp_addr;
    char *enbracket, *ports;
    char *tmp;
 
    if(addr == NULL)
    {
        ErrorMessage("ERROR %s(%d) => Undefine address in "
                     "portscan-ignorehosts directive, igoring.\n", file_name, 
                     file_line);

        return;
    }

    if(*addr == '!')
    {
        host->flags |= EXCEPT_SRC_IP;
        addr++;
    }
 
    if(*addr == '$')
    {
        if((tmp = VarGet(addr + 1)) == NULL)
        {
            ErrorMessage("ERROR %s (%d) => Undefined variable \"%s\", "
                         "ignoring\n", file_name, file_line, addr);

            return;
        }
    }
    else
    {
        tmp = addr;
    }
 
    ports = strrchr(tmp, (int)'@');

    if (*tmp == '[')
    {
        enbracket = strrchr(tmp, (int)']');
	if (enbracket) *enbracket = '\x0'; /* null out the en-bracket */
 
	if (ports && enbracket && (ports < enbracket))
	{
	  FatalError("[!] ERROR %s(%d) => syntax error in"
		     "portscan2-ignorehosts \"%s\"\n",
		     file_name, file_line, tmp);
	}	
        toks = mSplit(tmp+1, ",", 128, &num_toks, 0);
 
        for(i = 0; i < num_toks; i++)
        {
            tmp_addr = IgnoreAllocAddrNode(host);
 
            ParseIP(toks[i], tmp_addr);
        }

        mSplitFree(&toks, num_toks);
    }
    else
    {
        if (ports) *ports = '\x0'; /* null out the at */

        tmp_addr = IgnoreAllocAddrNode(host);

        ParseIP(tmp, tmp_addr);
    }

    if (ports)
    {
      ports++;
      if (ParsePort(ports, &(host->hsp), &(host->lsp), "ip", &not_flag))
	host->flags |= ANY_SRC_PORT;
      if (not_flag)
	host->flags |= EXCEPT_SRC_PORT;
    } else {
	host->flags |= ANY_SRC_PORT;
    }

}

/*************************************************************/
/* Called at runtime to establish the list of source ports   */
/* which are ignored by the portscan detector                */
/*************************************************************/
void InitIgnoreFrom(u_char *args)
{
  InitIgnorePorts(args, &ignorePortFrom, &num_ports_from);
}

/*************************************************************/
/* Called at runtime to establish the list of destination    */
/* ports which are ignored by the portscan detector          */
/*************************************************************/
void InitIgnoreTo(u_char *args)
{
  InitIgnorePorts(args, &ignorePortTo, &num_ports_to);
}

/*************************************************************/
/* Called at runtime to establish the lists of ports which   */
/* are ignored by the portscan detector                      */
/*************************************************************/
void InitIgnorePorts(u_char *list, u_int32_t **ports, int *num)
{
    int new_ports, max_ports;
    u_int32_t *pool;
    char **toks;
    int num_toks;

    *ports = NULL;
    *num = 0;
    max_ports = 0;

    if(list == NULL)
    {
        ErrorMessage(MODNAME ": ERROR: %s(%d)=> No arguments to "
                     "portscan2-ignoreports, ignoring.\n",
		     file_name, file_line);
        return;
    }
    
    toks = mSplit(list, " ", MAX_PORTS, &num_toks, '\\');

    for(;*num < num_toks; (*num)++)
    {
      if(*num >= max_ports)
      {
	new_ports = max_ports + MEM_CHUNK;
	if((pool = (u_int32_t *) calloc(new_ports, sizeof(u_int32_t))) == NULL)
	{
	  FatalError("[!] ERROR: Unable to allocate space for "
		     "portscan2-ignoreports");
	}
	if (*ports != NULL)
	{
	  memcpy(pool, *ports, max_ports * sizeof(u_int32_t));
	  free(*ports);
	}
	max_ports = new_ports;
	*ports = pool;
      }
      (*ports)[*num] = ScanParsePort(toks[*num]);
#ifdef DEBUG
      printf(MODNAME ": InitIgnorePorts(): Added port %u\n", 
	     (unsigned) (*ports)[*num]);
#endif  /* DEBUG */
    }

    mSplitFree(&toks, num_toks);

#ifdef DEBUG
    printf(MODNAME ": InitIgnorePorts(): %d port(s) added\n", *num);
#endif  /* DEBUG */
}

/*******************************************************************/
/* parses the ports in the ignore ports list                       */
/*******************************************************************/
u_int32_t ScanParsePort(char *port)
{
    char *tmp;
 
    if(port == NULL)
    {
      FatalError("ERROR %s(%d) => Undefined ports in "
		 "portscan2-ignoreports directive\n",
		 file_name, file_line);
    }

    if(*port == '$')
    {
      if((tmp = VarGet(port + 1)) == NULL)
        {
	  FatalError("ERROR %s (%d) => Undefined variable \"%s\"\n",
		     file_name, file_line, port);
	  
        }
    }
    else
    {
        tmp = port;
    }

    if(!isdigit((int)tmp[0]))
    {
      FatalError("ERROR %s(%d) => Bad port list to "
		 "portscan2-ignoreports\n", file_name, file_line);
    }
    return((u_int32_t)atol(tmp));
}


/************************************************************/
/* checks to see if a packet is coming from an ignored host */
/************************************************************/
int IsIgnored(Packet *p)
{
#ifdef DEBUG
    char sourceIP[16], ruleIP[16], ruleNetMask[16];
#endif
    HostNode *currentHost = ignoreList;
    int i;

    for(i = 0; i < num_ports_from; i++)
    {
      if (p->sp == ignorePortFrom[i])
      {
#ifdef DEBUG
            memset(sourceIP, '\0', 16);
            strncpy(sourceIP, inet_ntoa(p->iph->ip_src), 15);
            printf(MODNAME ": IsIgnored(): Source port %u from %s found!\n", 
                   (unsigned) p->sp, sourceIP);
#endif  /* DEBUG */
	return(1);
      }
    }

    for(i = 0; i < num_ports_to; i++)
    {
      if (p->dp == ignorePortTo[i])
      {
#ifdef DEBUG
            memset(sourceIP, '\0', 16);
            strncpy(sourceIP, inet_ntoa(p->iph->ip_src), 15);
            printf(MODNAME ": IsIgnored(): Destination port %u "
		   "from %s found!\n", 
                   (unsigned) p->dp, sourceIP);
#endif  /* DEBUG */
	return(1);
      }
    }			      
        
    while(currentHost)
    {
        /*
         * Return 1 if the source addr is in the serverlist, 0 if nothing is
         * found.
         */
        if(CheckAddrPort(currentHost->address, currentHost->hsp,
			 currentHost->lsp, p, currentHost->flags, CHECK_SRC))
        {
#ifdef DEBUG
            memset(sourceIP, '\0', 16);
            memset(ruleIP, '\0', 16);
            memset(ruleNetMask, '\0', 16);
            strncpy(sourceIP, inet_ntoa(p->iph->ip_src), 15);
            strncpy(ruleIP, inet_ntoa(*(struct in_addr*)
				      &(currentHost->address->ip_addr)), 14);
            strncpy(ruleNetMask, 
                    inet_ntoa(*(struct in_addr *)
			      &(currentHost->address->netmask)), 15);

            printf(MODNAME ": IsIgnored(): Server %s found in %s/%s!\n", 
                   sourceIP, ruleIP, ruleNetMask);
#endif  /* DEBUG */
            return(1);
        }

        currentHost = currentHost->nextNode;
    }

    return(0);
}


/********************************************************/
/* takes a target node and zeros out it's port list     */
/********************************************************/
INLINE void InitPortlist(ScanTarget *target)
{
    int i;
        
    for(i=0; i<65536/8; i++)
    {
        target->plist[i] = 0;
    }
}


/***************************************************/
/* Add a port # to the port array for the target.  */
/* This is called whenever a portscanner touches   */
/* a new port on a target.                         */
/***************************************************/
INLINE void AddTargetPort(ScanTarget *target, u_int16_t offset, Packet *p)
{
    /* target->plist is an array of char being treated as */
    /* a bitfield. There 65535 bits in the char array.    */
    /* Through a little voodoo we can set any particular  */
    /* bit in that field to 1, indicating the port has    */
    /* been hit. offset is the port # we wish to update   */
    target->plist[(offset/8)] |= 1<<(offset%8); /*  voodoo */
    /* increment the appropriate counters */
    target->port_count++;
    target->parent->port_count++;

    if(target->parent->port_count > ps2data.portThreshold)
    {
        if(target->parent->portsExceeded == FALSE) /* new ps, alert! */
        {
            SLog(p, 0, target->parent);
            SAlert(p, 0, target->parent);
            target->parent->portsExceeded = TRUE;
            /* dumpPacketStats(target->parent); */
        }
        else /*  old portscan, log the packet */
        {
            SLog(p, 0, target->parent);
        }
    }
}

/*********************************/
/* check to see if a port is set */
/*********************************/
INLINE int portIsSet(char *portlist, int offset)
{
    /* see comment in AddTargetPort regarding this */
    return portlist[(offset/8)] & (1<<(offset%8));
}


/**************************************************/
/* Add a target to a portscanners target tree.    */
/* Called whenever a new target is touched by     */
/* a portscanner                                  */
/**************************************************/
void AddTarget(Portscanner *ps, Packet *p)
{
    struct in_addr tmp;
    ScanTarget *target = NULL;
    MemBucket *mb = NULL;
    int pruned;
    
    /* grab a node from the target pool */
    mb = mempool_alloc(&ps2data.TargetPool);

    if(mb == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2, "Outta Target Nodes :(\n"););
        
        /*
         * force prune of the Portscanners ( those should have some
         * targets associated with them to free up )
         */

        pruned = PrunePortscanners(p->pkth->ts.tv_sec, 0, ps);

        if(pruned <= 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                    "Pruned got %d nodes --- forcing\n"););
            pruned = PrunePortscanners(p->pkth->ts.tv_sec, 5, ps);
        }

        mb = mempool_alloc(&ps2data.TargetPool);
    }

    if(mb == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                "[*] Outta Target Nodes -- stage2 returning\n"););
        return;
    }

    target = (ScanTarget *) mb->data;
    target->bucket = mb;
    
    /* target is guaranteed to be set at this point */
    
    /* fill in the target struct */
    target->target_ip = (u_int32_t)p->iph->ip_dst.s_addr;
    target->port_count = 1;
    target->initial_time.tv_sec = p->pkth->ts.tv_sec;
    target->last_time.tv_sec = p->pkth->ts.tv_sec;
    target->parent = ps;

    InitPortlist(target);  /*  zeros out the node's port list */

    /* insert the new target node into the tree */
    if(ubi_sptInsert(ps->targetRootPtr, (ubi_btNodePtr)target,
                     (ubi_btNodePtr)target, NULL) == ubi_trFALSE)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                "Insert into Targets failed\n"););
    }

    /* update the target count */
    target->parent->target_count++;
    
    /* update the targets port list */
    AddTargetPort(target, p->dp, p);
    
    /* check thresholds to see if this qualifies as a port scan */
    if(ps->target_count > ps2data.tgtThreshold)
    {
        if(ps->targetsExceeded == FALSE) /*  if FALSE, then new portscan */
        {
            tmp.s_addr = ps->scanner_ip;

            DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                    "Portscanner %s # targets exceeded\n",
                                    inet_ntoa(tmp)););
            
            SLog(p, 0, ps); /*  log the packet */
            SAlert(p, 0, ps); /*  generate an alert */
            ps->targetsExceeded = TRUE; /*  we have now alerted */
            /* dumpPacketStats(ps); */
        }
        else /* alert has already been generated so log the packet */
        {
            SLog(p, 0, ps);
        }
    }
}

/*****************************************************************/
/* Adds a new portscanner to the portscan tree, builds a target  */
/* tree for this portscanner.                                    */
/*****************************************************************/
void AddPortScanner(Packet *p)
{
    Portscanner *ps = NULL;
    MemBucket *mb = NULL;
    /* borrow a portscanner node from the portscanner node pool */
    mb = mempool_alloc(&ps2data.ScannerPool);

    if(mb == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2, "out of Scanner Nodes\n"););
        /* TBD -- free up one */
        return;
    }

    ps = (Portscanner *) mb->data;
    ps->bucket = mb;
    
    /* fill in the portscanner struct */
    ps->scanner_ip = (u_int32_t)p->iph->ip_src.s_addr;
    ps->last_time.tv_sec = p->pkth->ts.tv_sec;
    ps->initial_time.tv_sec = p->pkth->ts.tv_sec;
    ps->port_count = 0; /* Add target increments this */
    ps->target_count = 0; /* Add target increments this */
    ps->targetRootPtr = &ps->targetRoot;
    ps->portsExceeded = FALSE;
    ps->targetsExceeded = FALSE;

    DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                            "Assigning a scanner ip of %s\n",
                            inet_ntoa(p->iph->ip_src)););
    
    /* create a new target tree for this portscanner */
    if(ubi_trInitTree(ps->targetRootPtr, targetCompareFunc,
                      0) == ubi_trFALSE)
    {
        printf("init tree failed!\n");
    }
        
    /* Add the target to the target tree */
    AddTarget(ps, p);

    /* get the stats for the initiating packet */

    /* addPacketStats(ps, p);

       Need to figure out what I should do with this right here
    */

    /* add this scanner to the portscan tree */
    /* TBD -- error check */
    if(ubi_sptInsert(ps2data.ScannersPtr,
                     (ubi_btNodePtr)ps,
                     (ubi_btNodePtr)ps, NULL) == ubi_trFALSE)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                "Insert into Scanners failed\n"););
    }
}

/*********************************************************************/
/* Callback function used by splay trees to sort portscanner nodes   */
/*********************************************************************/
static int psCompareFunc(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    Portscanner *A = (Portscanner *) NodePtr;
    Portscanner *B = (Portscanner *) ItemPtr;
#ifdef DEBUG
    #define IPLEN 256
    char sip[IPLEN];

    strncpy(sip, inet_ntoa(*(struct in_addr *) &A->scanner_ip), IPLEN);
    DebugMessage(DEBUG_PORTSCAN2,"psCompareFunc %s %s\n",
                 sip,
                 inet_ntoa(*(struct in_addr *) &B->scanner_ip));
                 
    #undef IPLEN
#endif 
    
    
    
    if(A->scanner_ip < B->scanner_ip)
    {
        return 1;
    }
    else if(A->scanner_ip > B->scanner_ip)
    {
        return -1;
    }

    return 0;
}

/*********************************************************************/
/* Callback function used by splay trees to sort target nodes        */
/*********************************************************************/
static int targetCompareFunc(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    ScanTarget *A;
    ScanTarget *B;

    A = (ScanTarget *) NodePtr;
    B = (ScanTarget *) ItemPtr;

    if(A->target_ip < B->target_ip)
        return 1;
    else if(B->target_ip < A->target_ip)
        return -1;

    return 0;
}



/*
 * Generates a snort alert when a portscan is detected
 */
void SAlert(Packet *p, int scan_type, Portscanner *ps)
{
    Event event;
    char outstring[255];

    snprintf(outstring, 255, SCAN2_PREFIX_STR
             "%s: %d targets %d ports in %d seconds",
             inet_ntoa(*((struct in_addr *) &ps->scanner_ip)),
             ps->target_count,
             ps->port_count,
             (int) (p->pkth->ts.tv_sec - ps->initial_time.tv_sec));


    DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2, "%s\n", outstring););
    SetEvent(&event, GENERATOR_SPP_SCAN2, SCAN_TYPE, 1, 0, 0, 0);

    CallAlertFuncs(p, outstring, NULL, &event);
    ps->event_id = event.event_id;
}

/*******************************************************************/
/* Called for each packet of a portscan. Logs interesting packet   */
/* data to a text file                                             */
/*******************************************************************/
void SLog(Packet *p, int scan_type, Portscanner *ps)
{
    char src[STD_BUF];
    char dst[STD_BUF];
    char timestamp[TIMEBUF_SIZE];
    char flagString[9];

    strlcpy(src, inet_ntoa(p->iph->ip_src), 16);
    strlcpy(dst, inet_ntoa(p->iph->ip_dst), 16);
    ts_print((struct timeval *) &p->pkth->ts, timestamp);
    
    if(p->tcph)
    { 
        CreateTCPFlagString(p, flagString);
        fprintf(ps2data.logfile,"%s TCP src: %s dst: %s sport: %u dport: %u "
                "tgts: %u ports: %u flags: %s event_id: %u\n", timestamp, src, 
                dst, p->sp, p->dp, ps->target_count, ps->port_count, 
                flagString, ps->event_id);
    }
    else if(p->udph)
    {
        fprintf(ps2data.logfile, "%s UDP src: %s dst: %s sport: %u dport: %u "
                "tgts: %u ports: %u event_id: %u\n", timestamp, src, dst, 
                p->sp, p->dp, ps->target_count, ps->port_count, ps->event_id);
    }
    else if(p->icmph)
    {
        fprintf(ps2data.logfile, "%s ICMP src: %s dst: %s type: %u code: %u "
                "tgts: %u event_id: %u\n", timestamp, src, dst, p->icmph->type, 
                p->icmph->code, ps->target_count, ps->event_id);
    }
    
    fflush(ps2data.logfile);
}

/*********************************************************************/
/* This is the main dude. Called by spp_conversation each time a new */
/* session is established.                                           */
/*********************************************************************/
void psWatch(Packet *p)
{
    Portscanner tmp;
    Portscanner *returned;
    ScanTarget tgt;
    ScanTarget *rtgt;

#ifdef DEBUG
    #define IPLEN 256
    char sip[IPLEN];

    strncpy(sip, inet_ntoa(p->iph->ip_src), IPLEN);
    DebugMessage(DEBUG_PORTSCAN2,"In PsWatch... %s:%d->%s:%d state: %p\n",
                 sip,
                 p->dp,
                 inet_ntoa(p->iph->ip_dst),
                 p->sp);
    
    #undef IPLEN
#endif 

    /* check to see if this guy is on the ignored list, if so bail */
    if(IsIgnored(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,"Matched ignore list.\n"););        
        return;
    }

    /* search for this portscanner in the portscan tree */
    tmp.scanner_ip = (u_int32_t)p->iph->ip_src.s_addr;
    
    DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,"scanner_ip to lookfor: %s\n", inet_ntoa(p->iph->ip_src)););        
    returned = (Portscanner *) ubi_sptFind(ps2data.ScannersPtr, (ubi_btItemPtr)&tmp);

    if(returned == NULL)  /* we have a new potential scanner */
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                "Portscanner not found. Allocating\n", returned););
                
        AddPortScanner(p);
    } /* session already logged, get out */
    else        
    {

        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                "Found portscanner: %p, returned->scanner_ip: %s\n",
                                returned,
                                inet_ntoa(*(struct in_addr *) &returned->scanner_ip)););

        /* Portscanner found, new session, pdate target/port */
        returned->last_time.tv_sec = p->pkth->ts.tv_sec;

        tgt.target_ip = (u_int32_t)p->iph->ip_dst.s_addr;

        /* check to see if target has been hit before */
        rtgt = (ScanTarget *) ubi_sptFind((ubi_trRootPtr)returned->targetRootPtr, 
                                          (ubi_btItemPtr)&tgt);

        if(rtgt == NULL) /* no such target in target tree, add him */
        {
            /*  AddTarget calls AddTargetPort, so no need to call here */
            AddTarget(returned, p);
            
            /*              if((returned->targetsExceeded == FALSE) &&  */
            /*                 (returned->portsExceeded == FALSE)) */
            /*              { */
            /*                  addPacketStats(returned, p); */
            /*              } */
        }
        else  /* target found in target tree */
        {
            /* hasn't hit this port before */
            if(!portIsSet(rtgt->plist, p->dp))  
            {
                /* update the port list for the target */
                AddTargetPort(rtgt, p->dp, p);
                
                /*                  if ((returned->targetsExceeded == FALSE) &&  */
                /*                      (returned->portsExceeded == FALSE)) */
                /*                  { */
                /*                      addPacketStats(returned, p); */
                /*                  } */
            }

            if(p->pkth->ts.tv_sec >= (returned->initial_time.tv_sec + ps2data.timeout))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                        "Pruning out targets %p due to timeout\n",
                                        returned););
                
                /* Prune out old sessions... we work on a sliding window ya know */
                PruneTargets(returned, p->pkth->ts.tv_sec, 0);
                returned->initial_time.tv_sec = p->pkth->ts.tv_sec;
            }
        }
    }

    if(p->pkth->ts.tv_sec >= (ps2data.prune_time.tv_sec + ps2data.timeout))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                                "Pruning out scanners due to timeout\n"););

        /* Cull any expired sessions out */
        PrunePortscanners(p->pkth->ts.tv_sec, 0, NULL);
        ps2data.prune_time.tv_sec = p->pkth->ts.tv_sec;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2,
                            "leaving pswatch: Scanner count: %u\n",
                            ubi_trCount(ps2data.ScannersPtr)););
}

void SetupScan2(void)
{
    RegisterPreprocessor("portscan2", Scan2Init);
    RegisterPreprocessor("portscan2-ignorehosts", InitIgnoreHosts);
    RegisterPreprocessor("portscan2-ignoreports-from", InitIgnoreFrom);
    RegisterPreprocessor("portscan2-ignoreports-to", InitIgnoreTo);
}

/****************************************************/
/* Called at runtime to set everything up           */
/****************************************************/
void Scan2Init(u_char *args)
{
    struct timeval tv;
    struct timezone tz;

    memset(&ps2data, 0, sizeof(Portscan2Data));

    if(conv_data.isInitialized != 1)
    {
        FatalError("Please activate spp_conversation before"
                   " trying to activate spp_portscan2\n");
    }   

    LogMessage ("Portscan2 config:\n");
    ParseScanmungeArgs(args);
    gettimeofday(&tv, &tz);

    ps2data.ScannersPtr = &ps2data.Scanners;
    
    /* set up the portscanner tree */ 
    ubi_trInitTree(ps2data.ScannersPtr, psCompareFunc, 0);

    /* set up the node pools */
    if(mempool_init(&ps2data.ScannerPool,
                    ps2data.scanner_count,
                    sizeof(Portscanner)))
    {
        FatalError("ERROR: Can't initialize mempool for Scanners\n");
    }
    
    if(mempool_init(&ps2data.TargetPool , ps2data.target_count,  sizeof(ScanTarget)))
    {
        FatalError("ERROR: Can't initialize mempool for Targets\n");
    }

    ps2data.isInitialized = 1;
    conv_data.watch_scans = 1;
}

static void DeleteTarget(ScanTarget *target)
{
    mempool_free(&ps2data.TargetPool,target->bucket);
}


static void DeletePortscanner(Portscanner *ps)
{
    Portscanner *oldps;
    
    /* need to do a walk and delete all the targets */
    DEBUG_WRAP(DebugMessage(DEBUG_PORTSCAN2, "Deleteing portscanner %p\n", ps);
               DebugMessage(DEBUG_PORTSCAN2,
                            "ps->scanner_ip: %X\n", ps->scanner_ip);
               DebugMessage(DEBUG_PORTSCAN2,
                            "ps->initial_time: %u\n", ps->initial_time.tv_sec);
               DebugMessage(DEBUG_PORTSCAN2,
                            "ps->last_time: %u\n", ps->last_time.tv_sec);
               DebugMessage(DEBUG_PORTSCAN2,
                            "ps->targetRootPtr: %p\n", ps->targetRootPtr);

               );

    (void)ubi_trKillTree(ps->targetRootPtr, DeleteTarget);

    
    oldps = (Portscanner *) ubi_sptRemove(ps2data.ScannersPtr,
                                          (ubi_btNodePtr) ps);
        
    mempool_free(&ps2data.ScannerPool,ps->bucket);
}


/* look familiar! I thought it did.  hate redebugging this junk */
static int PruneTargets(Portscanner *p, u_int32_t now, int tokill)
{
    ScanTarget *idx;
    u_int32_t pruned = 0;

    if(ubi_trCount(p->targetRootPtr) == 0)
    {
        return 0;
    }

    /* Number of things that need to be deleted */
    if(tokill == 0)
    {
        idx = (ScanTarget *) ubi_btFirst((ubi_btNodePtr)p->targetRootPtr);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            if((idx->last_time.tv_sec + ps2data.timeout) > now)
            {
                ScanTarget *savidx = idx;

                if(ubi_trCount(p->targetRootPtr) > 1)
                {
                    idx = (ScanTarget *) ubi_btNext((ubi_btNodePtr)idx);
                    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                            "pruning stale target\n"););

                    p->port_count -= savidx->port_count;
                    p->target_count--;              
                    savidx = (ScanTarget *)ubi_sptRemove(p->targetRootPtr, (ubi_btNodePtr) savidx);
                    DeleteTarget(savidx);
                    pruned++;
                }
                else
                {
                    p->port_count -= savidx->port_count;
                    p->target_count--;
                    savidx = (ScanTarget *)ubi_sptRemove(p->targetRootPtr, (ubi_btNodePtr) savidx);
                    DeleteTarget(savidx);
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                if(idx != NULL && ubi_trCount(p->targetRootPtr))
                {
                    idx = (ScanTarget *) ubi_btNext((ubi_btNodePtr)idx);
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
        while(tokill-- &&  ubi_trCount(p->targetRootPtr) > 1)
        {
            idx = (ScanTarget *) ubi_btLeafNode((ubi_btNodePtr)p->targetRootPtr);
            p->target_count--;
            DeleteTarget(idx);
        }
        return 0;
    }

    return 0;
}

static int PrunePortscanners(u_int32_t now, int tokill, Portscanner *saveme)
{
    Portscanner *idx;
    u_int32_t pruned = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                            "Pruneport scanners called now: "
                            " %u tokill: %d: saveme: %p, count: %u\n",
                            now, tokill, saveme,
                            ubi_trCount(ps2data.ScannersPtr)););
    
    if(ubi_trCount(ps2data.ScannersPtr) <= 1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                "1 or less to prune. returning\n"););
        return 0;
    }

    /* Number of things that need to be deleted */
    if(tokill == 0)
    {
        idx = (Portscanner *) ubi_btFirst((ubi_btNodePtr)ps2data.ScannersPtr->root);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            if(idx == saveme)
            {
                idx = (Portscanner *) ubi_btNext((ubi_btNodePtr)idx);
                continue;
            }

            if((idx->last_time.tv_sec+ps2data.timeout) > now)
            {
                Portscanner *savidx = idx;

                if(ubi_trCount(ps2data.ScannersPtr) > 1)
                {
                    idx = (Portscanner *) ubi_btNext((ubi_btNodePtr)idx);
                    DEBUG_WRAP(DebugMessage(DEBUG_CONVERSATION,
                                            "pruning stale portscanner\n"););
                    DeletePortscanner(savidx);
                    pruned++;
                }
                else
                {
                    DeletePortscanner(savidx);
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                if(idx != NULL && ubi_trCount(ps2data.ScannersPtr))
                {
                    idx = (Portscanner *) ubi_btNext((ubi_btNodePtr)idx);
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
        while(tokill-- &&  ubi_trCount(ps2data.ScannersPtr) > 1)
        {
            idx = (Portscanner *) ubi_btLeafNode((ubi_btNodePtr)ps2data.ScannersPtr);
            DeletePortscanner(idx);
        }
        return 0;
    }

    return 0;
}
