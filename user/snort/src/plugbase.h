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
#ifndef __PLUGBASE_H__
#define __PLUGBASE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"

#ifndef WIN32
    #include <sys/ioctl.h>
#endif  /* !WIN32 */


#ifdef ENABLE_SSL
    #ifdef Free
/* Free macro in radix.h if defined, will conflict with OpenSSL definition */
        #undef Free
    #endif
#endif

#ifndef WIN32
    #include <net/route.h>
#endif /* !WIN32 */
#ifdef ENABLE_SSL
    #undef Free
#endif

#if defined(SOLARIS) || defined(FREEBSD) || defined(OPENBSD)
    #include <sys/param.h>
#endif

#if defined(FREEBSD) || defined(OPENBSD) || defined(NETBSD) || defined(OSF1)
    #include <sys/mbuf.h>
#endif

#ifndef IFNAMSIZ /* IFNAMSIZ is defined in all platforms I checked.. */
    #include <net/if.h>
#endif


#define SMALLBUFFER 32

#define NT_OUTPUT_ALERT   0x1  /* output node type alert */
#define NT_OUTPUT_LOG     0x2  /* output node type log */
#define NT_OUTPUT_SPECIAL 0x4  /* special output node type */

#define DETECTION_KEYWORD 0
#define RESPONSE_KEYWORD 1

/*
**  Preprocessor Communication Defines
**  ----------------------------------
**  These defines allow preprocessors to be turned
**  on and off for each packet.  Preprocessors can be
**  turned off and on before preprocessing occurs and
**  during preprocessing.
**
**  Currently, the order in which the preprocessors are
**  placed in the snort.conf determine the order of 
**  evaluation.  So if one module wants to turn off
**  another module, it must come first in the order.
*/
#define PP_ALL                    -1
#define PP_LOADBALANCING          1
#define PP_PORTSCAN               2
#define PP_HTTPINSPECT            4
#define PP_PORTSCAN_IGNORE_HOSTS  8
#define PP_RPCDECODE              16
#define PP_BO                     32
#define PP_TELNEG                 64
#define PP_STREAM4                128
#define PP_FRAG2                  256
#define PP_ARPSPOOF               512
#define PP_ASN1DECODE             1024
#define PP_FNORD                  2048
#define PP_CONVERSATION           4096
#define PP_PORTSCAN2              8192
#define PP_HTTPFLOW               16384
#define PP_PERFMONITOR            32768
#define PP_STREAM4_REASSEMBLE    65536

/**************************** Detection Plugin API ****************************/

typedef struct _KeywordXlate
{
    char *keyword;
    void (*func)(char *, OptTreeNode *, int);
} KeywordXlate;


typedef struct _KeywordXlateList
{
    KeywordXlate entry;
    struct _KeywordXlateList *next;
} KeywordXlateList;

void InitPlugIns();
void RegisterPlugin(char *, void (*func)(char *, OptTreeNode *, int));
void DumpPlugIns();
OptFpList *AddOptFuncToList(int (*func)(Packet *, struct _OptTreeNode*, 
            struct _OptFpList*), OptTreeNode *);
void AddRspFuncToList(int (*func) (Packet *, struct _RspFpList *), 
                      OptTreeNode *, void *);



/************************** End Detection Plugin API **************************/

/***************************** Preprocessor API *******************************/
typedef struct _PreprocessKeywordNode
{
    char *keyword;
    void (*func)(char *);

} PreprocessKeywordNode;

typedef struct _PreprocessKeywordList
{
    PreprocessKeywordNode entry;
    struct _PreprocessKeywordList *next;

} PreprocessKeywordList;

typedef struct _PreprocessFuncNode
{
    void (*func)(Packet *);
    struct _PreprocessFuncNode *next;

} PreprocessFuncNode;

void InitPreprocessors();
void RegisterPreprocessor(char *, void (*func)(u_char *));
void DumpPreprocessors();
void AddFuncToPreprocList(void (*func)(Packet *));

/*************************** End Preprocessor API *****************************/

typedef struct _PluginSignalFuncNode
{
    void (*func)(int, void*);
    void *arg;
    struct _PluginSignalFuncNode *next;

} PluginSignalFuncNode;

int PacketIsIP(Packet *);
int PacketIsTCP(Packet *);
int PacketIsUDP(Packet *);
int PacketIsICMP(Packet *);
int DestinationIpIsHomenet(Packet *);
int SourceIpIsHomenet(Packet *);
int IsTcpSessionTraffic(Packet *);
int CheckNet(struct in_addr *, struct in_addr *);
void AddFuncToRestartList(void (*func)(int, void*), void*);
void AddFuncToCleanExitList(void (*func)(int, void*), void*);
PluginSignalFuncNode *AddFuncToSignalList(void (*func)(int, void*), void*, PluginSignalFuncNode *);




#define ENCODING_HEX 0
#define ENCODING_BASE64 1
#define ENCODING_ASCII 2
#define DETAIL_FAST  0 
#define DETAIL_FULL  1

char *GetUniqueName(char *);
char *GetIP(char *);
char *GetHostname();
int GetLocalTimezone();

/***********************************************************
 If you use any of the functions in this section, you need 
 to call free() on the char * that is returned after you are 
 done using it. Otherwise, you will have created a memory 
 leak.
***********************************************************/
char *GetTimestamp(register const struct timeval *, int);
char *GetCurrentTimestamp();
char *base64(u_char *, int);
char *ascii(u_char *, int);
char *hex(u_char *, int);
char *fasthex(u_char *, int);
char *int2s(int);
char *hex2s(int);
char *str2s(char *);
/**********************************************************/

#endif /* __PLUGBASE_H__ */
