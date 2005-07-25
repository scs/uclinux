/* $Id$ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#ifndef WIN32
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <limits.h>
#endif /* !WIN32 */
#include <fcntl.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "snort.h"
#include "mstring.h"
#include "debug.h"
#include "util.h"
#include "parser.h"
#include "inline.h"

#ifdef WIN32
#include "win32/WIN32-Code/name.h"
#endif

#ifdef PATH_MAX
#define PATH_MAX_UTIL PATH_MAX
#else
#define PATH_MAX_UTIL 1024
#endif /* PATH_MAX */


/*
 * Function: GenHomenet(char *)
 *
 * Purpose: Translate the command line character string into its equivalent
 *          32-bit network byte ordered value (with netmask)
 *
 * Arguments: netdata => The address/CIDR block
 *
 * Returns: void function
 */
void GenHomenet(char *netdata)
{
    struct in_addr net;    /* place to stick the local network data */
    char **toks;           /* dbl ptr to store mSplit return data in */
    int num_toks;          /* number of tokens mSplit returns */
    int nmask;             /* temporary netmask storage */

    /* break out the CIDR notation from the IP address */
    toks = mSplit(netdata, "/", 2, &num_toks, 0);

    if(num_toks > 1)
    {
        /* convert the CIDR notation into a real live netmask */
        nmask = atoi(toks[1]);

        if((nmask > 0) && (nmask < 33))
        {
            pv.netmask = netmasks[nmask];
        }
        else
        {
            FatalError("Bad CIDR block [%s:%d], 1 to 32 please!\n",
                       toks[1], nmask);
        }
    }
    else
    {
        FatalError("No netmask specified for home network!\n");
    }

    pv.netmask = htonl(pv.netmask);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "homenet netmask = %#8lX\n", pv.netmask););

    /* convert the IP addr into its 32-bit value */
    if((net.s_addr = inet_addr(toks[0])) == -1)
    {
        FatalError("Homenet (%s) didn't translate\n",
                   toks[0]);
    }
    else
    {
#ifdef DEBUG
        struct in_addr sin;

        DebugMessage(DEBUG_INIT, "Net = %s (%X)\n", inet_ntoa(net), net.s_addr);
#endif
        /* set the final homenet address up */
        pv.homenet = ((u_long) net.s_addr & pv.netmask);

#ifdef DEBUG
        sin.s_addr = pv.homenet;
        DebugMessage(DEBUG_INIT, "Homenet = %s (%X)\n", inet_ntoa(sin), sin.s_addr);
#endif
    }

    mSplitFree(&toks, num_toks);
}



void GenObfuscationMask(char *netdata)
{
    struct in_addr net;       /* place to stick the local network data */
    char **toks;              /* dbl ptr to store mSplit return data in */
    int num_toks;             /* number of tokens mSplit returns */
    int nmask;                /* temporary netmask storage */

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Got obfus data: %s\n", netdata););

    /* break out the CIDR notation from the IP address */
    toks = mSplit(netdata, "/", 2, &num_toks, 0);

    if(num_toks > 1)
    {
        /* convert the CIDR notation into a real live netmask */
        nmask = atoi(toks[1]);

        if((nmask > 0) && (nmask < 33))
        {
            pv.obfuscation_mask = netmasks[nmask];
        }
        else
        {
            FatalError("Bad CIDR block in obfuscation mask [%s:%d], "
                       "1 to 32 please!\n", toks[1], pv.obfuscation_mask);
        }
    }
    else
    {
        FatalError("No netmask specified for obsucation mask!\n");
    }

    pv.obfuscation_mask = htonl(pv.obfuscation_mask);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "obfuscation netmask = %#8lX\n", 
                pv.obfuscation_mask););

    /* convert the IP addr into its 32-bit value */
    if((net.s_addr = inet_addr(toks[0])) == -1)
    {
        FatalError("Obfuscation mask (%s) didn't translate\n",
                   toks[0]);
    }
    else
    {
        struct in_addr sin;

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Obfuscation Net = %s (%X)\n", 
                inet_ntoa(net), net.s_addr););

        /* set the final homenet address up */
        pv.obfuscation_net = ((u_long) net.s_addr & pv.obfuscation_mask);

        sin.s_addr = pv.obfuscation_net;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Obfuscation Net = %s (%X)\n", 
                inet_ntoa(sin), sin.s_addr););
        pv.obfuscation_mask = ~pv.obfuscation_mask;
    }

    mSplitFree(&toks, num_toks);
}

/****************************************************************************
 *
 * Function  : DefineIfaceVar()
 * Purpose   : Assign network address and network mast to IFACE_ADDR_VARNAME
 *             variable.
 * Arguments : interface name (string) netaddress and netmask (4 octets each)
 * Returns   : void function
 *
 ****************************************************************************/
void DefineIfaceVar(char *iname, u_char * network, u_char * netmask)
{
    char valbuf[32];
    char varbuf[BUFSIZ];

    snprintf(varbuf, BUFSIZ, "%s_ADDRESS", iname);

    snprintf(valbuf, 32, "%d.%d.%d.%d/%d.%d.%d.%d",
            network[0] & 0xff, network[1] & 0xff, network[2] & 0xff, 
            network[3] & 0xff, netmask[0] & 0xff, netmask[1] & 0xff, 
            netmask[2] & 0xff, netmask[3] & 0xff);

    VarDefine(varbuf, valbuf);
}


/****************************************************************************
 *
 * Function: CalcPct(float, float)
 *
 * Purpose:  Calculate the percentage of a value compared to a total
 *
 * Arguments: cnt => the numerator in the equation
 *            total => the denominator in the calculation
 *
 * Returns: pct -> the percentage of cnt to value
 *
 ****************************************************************************/
float CalcPct(float cnt, float total)
{
    float pct;

    if(cnt > 0.0)
        pct = cnt / total;
    else
        return 0.0;

    pct *= 100.0;

    return pct;
}


/****************************************************************************
 *
 * Function: DisplayBanner()
 *
 * Purpose:  Show valuable proggie info
 *
 * Arguments: None.
 *
 * Returns: 0 all the time
 *
 ****************************************************************************/
int DisplayBanner()
{
    fprintf(stderr, "\n"
        "   ,,_     -*> Snort! <*-\n"
        "  o\"  )~   Version %s (Build %s)\n"
        "   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/team.html\n"
        "           (C) Copyright 1998-2004 Sourcefire Inc., et al.\n"   
        "\n"
        , VERSION, BUILD);

    return 0;
}



/****************************************************************************
 *
 * Function: ts_print(register const struct, char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision.  Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 *
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void ts_print(register const struct timeval *tvp, char *timebuf)
{
    register int s;
    int    localzone;
    time_t Time;
    struct timeval tv;
    struct timezone tz;
    struct tm *lt;    /* place to stick the adjusted clock data */

    /* if null was passed, we use current time */
    if(!tvp)
    {
        /* manual page (for linux) says tz is never used, so.. */
        bzero((char *) &tz, sizeof(tz));
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    localzone = thiszone;
   
    /*
    **  If we're doing UTC, then make sure that the timezone is correct.
    */
    if(pv.use_utc)
        localzone = 0;
        
    s = (tvp->tv_sec + localzone) % 86400;
    Time = (tvp->tv_sec + localzone) - s;

    lt = gmtime(&Time);

    if(pv.include_year)
    {
        (void) snprintf(timebuf, TIMEBUF_SIZE, 
                        "%02d/%02d/%02d-%02d:%02d:%02d.%06u ", 
                        lt->tm_mon + 1, lt->tm_mday, lt->tm_year - 100, 
                        s / 3600, (s % 3600) / 60, s % 60, 
                        (u_int) tvp->tv_usec);
    } 
    else 
    {
        (void) snprintf(timebuf, TIMEBUF_SIZE,
                        "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon + 1,
                        lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
                        (u_int) tvp->tv_usec);
    }
}



/****************************************************************************
 *
 * Function: gmt2local(time_t)
 *
 * Purpose: Figures out how to adjust the current clock reading based on the
 *          timezone you're in.  Ripped off from TCPdump.
 *
 * Arguments: time_t => offset from GMT
 *
 * Returns: offset seconds from GMT
 *
 ****************************************************************************/
int gmt2local(time_t t)
{
    register int dt, dir;
    register struct tm *gmt, *loc;
    struct tm sgmt;

    if(t == 0)
        t = time(NULL);

    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);

    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
        (loc->tm_min - gmt->tm_min) * 60;

    dir = loc->tm_year - gmt->tm_year;

    if(dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;

    dt += dir * 24 * 60 * 60;

    return(dt);
}




/****************************************************************************
 *
 * Function: copy_argv(u_char **)
 *
 * Purpose: Copies a 2D array (like argv) into a flat string.  Stolen from
 *          TCPDump.
 *
 * Arguments: argv => 2D array to flatten
 *
 * Returns: Pointer to the flat string
 *
 ****************************************************************************/
char *copy_argv(char **argv)
{
    char **p;
    u_int len = 0;
    char *buf;
    char *src, *dst;
    void ftlerr(char *,...);

    p = argv;
    if(*p == 0)
        return 0;

    while(*p)
        len += strlen(*p++) + 1;

    buf = (char *) malloc(len);

    if(buf == NULL)
    {
        FatalError("malloc() failed: %s\n", strerror(errno));
    }
    p = argv;
    dst = buf;

    while((src = *p++) != NULL)
    {
        while((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }

    dst[-1] = '\0';

    return buf;
}


/****************************************************************************
 *
 * Function: strip(char *)
 *
 * Purpose: Strips a data buffer of CR/LF/TABs.  Replaces CR/LF's with
 *          NULL and TABs with spaces.
 *
 * Arguments: data => ptr to the data buf to be stripped
 *
 * Returns: size of the newly stripped string
 *
 ****************************************************************************/
int strip(char *data)
{
    int size;
    char *end;
    char *idx;

    idx = data;
    end = data + strlen(data);
    size = end - idx;

    while(idx != end)
    {
        if((*idx == '\n') ||
                (*idx == '\r'))
        {
            *idx = 0;
            size--;
        }
        if(*idx == '\t')
        {
            *idx = ' ';
        }
        idx++;
    }

    return size;
}


/****************************************************************************
 *
 * Function: InitNetMasks()
 *
 * Purpose: Loads the netmask struct in network order.  Yes, I know I could
 *          just load the array when I define it, but this is what occurred
 *          to me when I wrote this at 3:00 AM.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
extern u_long netmasks[33]; /* defined in snort.c */

void InitNetmasks()
{
    netmasks[0] = 0x0;
    netmasks[1] = 0x80000000;
    netmasks[2] = 0xC0000000;
    netmasks[3] = 0xE0000000;
    netmasks[4] = 0xF0000000;
    netmasks[5] = 0xF8000000;
    netmasks[6] = 0xFC000000;
    netmasks[7] = 0xFE000000;
    netmasks[8] = 0xFF000000;
    netmasks[9] = 0xFF800000;
    netmasks[10] = 0xFFC00000;
    netmasks[11] = 0xFFE00000;
    netmasks[12] = 0xFFF00000;
    netmasks[13] = 0xFFF80000;
    netmasks[14] = 0xFFFC0000;
    netmasks[15] = 0xFFFE0000;
    netmasks[16] = 0xFFFF0000;
    netmasks[17] = 0xFFFF8000;
    netmasks[18] = 0xFFFFC000;
    netmasks[19] = 0xFFFFE000;
    netmasks[20] = 0xFFFFF000;
    netmasks[21] = 0xFFFFF800;
    netmasks[22] = 0xFFFFFC00;
    netmasks[23] = 0xFFFFFE00;
    netmasks[24] = 0xFFFFFF00;
    netmasks[25] = 0xFFFFFF80;
    netmasks[26] = 0xFFFFFFC0;
    netmasks[27] = 0xFFFFFFE0;
    netmasks[28] = 0xFFFFFFF0;
    netmasks[29] = 0xFFFFFFF8;
    netmasks[30] = 0xFFFFFFFC;
    netmasks[31] = 0xFFFFFFFE;
    netmasks[32] = 0xFFFFFFFF;
}

/*
 * error message printing routines. in daemon mode these would go into
 * syslog.
 *
 * first would allow to print formatted error messages (similar to printf) and
 * the second is similar to perror.
 *
 */

void PrintError(char *str)
{
    if(pv.daemon_flag)
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "%s:%m", str);
    else
        perror(str);
}


/*
 * Function: ErrorMessage(const char *, ...)
 *
 * Purpose: Print a message to stderr.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void ErrorMessage(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    if(pv.daemon_flag)
    {
        vsnprintf(buf, STD_BUF, format, ap);
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}

/*
 * Function: LogMessage(const char *, ...)
 *
 * Purpose: Print a message to stdout or with logfacility.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void LogMessage(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    if(pv.quiet_flag && !pv.daemon_flag)
        return;

    va_start(ap, format);

    if(pv.daemon_flag)
    {
        vsnprintf(buf, STD_BUF, format, ap);
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}


/*
 * Function: CreateApplicationEventLogEntry(const char *)
 *
 * Purpose: Add an entry to the Win32 "Application" EventLog
 *
 * Arguments: szMessage => the formatted error string to print out
 *
 * Returns: void function
 */
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
void CreateApplicationEventLogEntry(const char *msg)
{
    HANDLE hEventLog; 
    char*  pEventSourceName = "SnortService";

    /* prepare to write to Application log on local host
      * with Event Source of SnortService
      */
    AddEventSource(pEventSourceName);
    hEventLog = RegisterEventSource(NULL, pEventSourceName);
    if (hEventLog == NULL)
    {
        /* Could not register the event source. */
        return;
    }
 
    if (!ReportEvent(hEventLog,   /* event log handle               */
            EVENTLOG_ERROR_TYPE,  /* event type                     */
            0,                    /* category zero                  */
            EVMSG_SIMPLE,         /* event identifier               */
            NULL,                 /* no user security identifier    */
            1,                    /* one substitution string        */
            0,                    /* no data                        */
            &msg,                 /* pointer to array of strings    */
            NULL))                /* pointer to data                */
    {
        /* Could not report the event. */
    }
 
    DeregisterEventSource(hEventLog); 
} 
#endif  /* WIN32 && ENABLE_WIN32_SERVICE */


/*
 * Function: FatalError(const char *, ...)
 *
 * Purpose: When a fatal error occurs, this function prints the error message
 *          and cleanly shuts down the program
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void FatalError(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    vsnprintf(buf, STD_BUF, format, ap);

    if(pv.daemon_flag)
    {
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "FATAL ERROR: %s", buf);
    }
    else
    {
        fprintf(stderr, "ERROR: %s", buf);
        fprintf(stderr,"Fatal Error, Quitting..\n");
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
        CreateApplicationEventLogEntry(buf);
#endif
    }

    exit(1);
}

void FatalPrintError(char *msg)
{
    PrintError(msg);
    exit(1);
}

/****************************************************************************
 *
 * Function: CreatePidFile(char *)
 *
 * Purpose:  Creates a PID file
 *
 * Arguments: Interface opened.
 *
 * Returns: void function
 *
 ****************************************************************************/
void CreatePidFile(char *intf)
{
    FILE *pid_file;
    struct stat pt;
#ifdef WIN32
    char dir[STD_BUF + 1];
#endif

    if (!pv.readmode_flag) 
    {
        if(!pv.quiet_flag)
        {
            LogMessage("Checking PID path...\n");
        }
#ifndef _PATH_VARRUN
#ifndef WIN32
        strlcpy(_PATH_VARRUN, "/var/run/", 10);
#else
        if (GetCurrentDirectory(sizeof (dir)-1, dir))
            strncpy (_PATH_VARRUN, dir, sizeof(dir)-1);
#endif  /* WIN32 */
#else
        if(!pv.quiet_flag)
        {
            LogMessage("PATH_VARRUN is set to %s on this operating system\n", 
                    _PATH_VARRUN);
        }
#endif  /* _PATH_VARRUN */

        stat(_PATH_VARRUN, &pt);

        if(!S_ISDIR(pt.st_mode) || access(_PATH_VARRUN, W_OK) == -1)
        {
            LogMessage("WARNING: _PATH_VARRUN is invalid, trying "
                    "/var/log...\n");
            strncpy(pv.pid_path, "/var/log/", strlen("/var/log/"));
            stat(pv.pid_path, &pt);

            if(!S_ISDIR(pt.st_mode) || access(pv.pid_path, W_OK) == -1)
            {
                LogMessage("WARNING: %s is invalid, logging Snort "
                        "PID path to log directory (%s)\n", pv.pid_path,
                        pv.log_dir);
                snprintf(pv.pid_path, STD_BUF, "%s/", pv.log_dir);
            }
        }
        else
        {
            LogMessage("PID path stat checked out ok, PID path set to %s\n", _PATH_VARRUN);
            strlcpy(pv.pid_path, _PATH_VARRUN, STD_BUF);
        }
    }

    if(intf == NULL || pv.pid_path == NULL)
    {
        /* pv.pid_path should have some value by now
         *          * so let us just be sane.
         *                   */
        FatalError("CreatePidFile() failed to lookup interface or pid_path is unknown!\n");
    }

    snprintf(pv.pid_filename, STD_BUF,  "%s/snort_%s%s.pid", pv.pid_path, intf,
            pv.pidfile_suffix);

    pid_file = fopen(pv.pid_filename, "w");

    if(pid_file)
    {
        int pid = (int) getpid();

        LogMessage("Writing PID \"%d\" to file \"%s\"\n", pid, pv.pid_filename);
        fprintf(pid_file, "%d\n", pid);
        fclose(pid_file);
    }
    else
    {
        ErrorMessage("Failed to create pid file %s", pv.pid_filename);
        pv.pid_filename[0] = 0;
    }
}


/****************************************************************************
 *
 * Function: SetUidGid(char *)
 *
 * Purpose:  Sets safe UserID and GroupID if needed
 *
 * Arguments: none
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetUidGid(void)
{
#ifndef WIN32

    if(groupname != NULL)
    {
        if(InlineMode())
        {
            ErrorMessage("Cannot set uid and gid when running Snort in "
                "inline mode.\n");

            return;
        }

        if(setgid(groupid) < 0)
            FatalError("Can not set gid: %lu\n", (u_long) groupid);

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Set gid to %lu\n", groupid););
    }
    if(username != NULL)
    {
        if(InlineMode())
        {
            ErrorMessage("Cannot set uid and gid when running Snort in "
                "inline mode.\n");

            return;
        }

        if(getuid() == 0 && initgroups(username, groupid) < 0)
            FatalError("Can not initgroups(%s,%lu)",
                    username, (u_long) groupid);

        /** just to be on a safe side... **/
        endgrent();
        endpwent();

        if(setuid(userid) < 0)
            FatalError("Can not set uid: %lu\n", (u_long) userid);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Set gid to %lu\n", groupid););
    }
#endif  /* WIN32 */

    return;
}

/* need int parameter here because of function declaration of signal(2) */
void DropStats(int iParamIgnored)
{
    struct pcap_stat ps;
    float drop = 0.0;
    float recv = 0.0;

    if(pv.quiet_flag)
        return;

    puts("\n\n===============================================================================\n");

    /*
     * you will hardly run snort in daemon mode and read from file i that is
     * why no `LogMessage()' here
     */
    if(pv.readmode_flag || InlineMode())
    {

        /* this wildass line adjusts for the fragment reassembly packet injector */
        recv = (float) (pc.tcp
                + pc.udp 
                + pc.icmp
                + pc.arp
                + pc.ipx
                + pc.eapol
                + pc.ipv6
                + pc.other
                + pc.discards
                + pc.rebuild_element
                - pc.rebuilt_frags
                - pc.frag_timeout);

        printf("Snort processed %u packets.\n", (unsigned int) recv);
    }
    else
    {
        /* collect the packet stats */
        if(pcap_stats(pd, &ps))
        {
            pcap_perror(pd, "pcap_stats");
        }
        else
        {
            recv = (float) ps.ps_recv;
            drop = (float) ps.ps_drop;

            LogMessage("Snort received %u packets\n", ps.ps_recv);
            LogMessage("    Analyzed: %u(%.3f%%)\n", ps.ps_recv - ps.ps_drop, 
                    ps.ps_recv?CalcPct((float)(ps.ps_recv-ps.ps_drop), 
                        (float) ps.ps_recv):0);
            LogMessage("    Dropped: %u(%.3f%%)\n", ps.ps_drop, 
                    ps.ps_recv?CalcPct((float)ps.ps_drop, (float) ps.ps_recv):0);
        }
    }

    LogMessage("================================================"
            "===============================\n");

    LogMessage("Breakdown by protocol:\n");
    LogMessage("    TCP: %-10lu (%.3f%%)%-*s\n", 
            pc.tcp, CalcPct((float) pc.tcp, recv), 
            CalcPct((float)pc.tcp,recv + drop)<10?10:9 , " ");
    LogMessage("    UDP: %-10lu (%.3f%%)%-*s\n", 
            pc.udp, CalcPct((float) pc.udp, recv),  
            CalcPct((float)pc.udp,recv + drop)<10?10:9, " ");
    LogMessage("   ICMP: %-10lu (%.3f%%)%-*s\n", 
            pc.icmp, CalcPct((float) pc.icmp, recv), 
            CalcPct((float)pc.icmp,recv + drop)<10?10:9, " ");
    LogMessage("    ARP: %-10lu (%.3f%%)\n", 
            pc.arp, CalcPct((float) pc.arp, recv));
    LogMessage("  EAPOL: %-10lu (%.3f%%)\n", 
            pc.eapol, CalcPct((float) pc.eapol, recv));
    LogMessage("   IPv6: %-10lu (%.3f%%)\n", 
            pc.ipv6, CalcPct((float) pc.ipv6, recv));
    LogMessage("    IPX: %-10lu (%.3f%%)\n", 
            pc.ipx, CalcPct((float) pc.ipx, recv));
    LogMessage("  OTHER: %-10lu (%.3f%%)\n", 
            pc.other, CalcPct((float) pc.other, recv));
    LogMessage("DISCARD: %-10lu (%.3f%%)\n", 
            pc.discards, CalcPct((float) pc.discards, recv));

    LogMessage("================================================"
            "===============================\n");
    LogMessage("Action Stats:\n");
    LogMessage("ALERTS: %u\n", pc.alert_pkts);
    LogMessage("LOGGED: %u\n", pc.log_pkts);
    LogMessage("PASSED: %u\n", pc.pass_pkts);

#ifdef DLT_IEEE802_11
    if(datalink == DLT_IEEE802_11)
    {
        LogMessage("================================================"
                "===============================\n");
        LogMessage("Wireless Stats:\n");
        LogMessage("Breakdown by type:\n");
        LogMessage("    Management Packets: %-10lu (%.3f%%)\n", 
                pc.wifi_mgmt, CalcPct((float) pc.wifi_mgmt, recv));
        LogMessage("    Control Packets:    %-10lu (%.3f%%)\n", 
                pc.wifi_control, CalcPct((float) pc.wifi_control, recv));
        LogMessage("    Data Packets:       %-10lu (%.3f%%)\n", 
                pc.wifi_data, CalcPct((float) pc.wifi_data, recv));
    }
#endif

    if(pc.frags > 0)
    {
        LogMessage("================================================"
                "===============================\n");
        LogMessage("Fragmentation Stats:\n");
        LogMessage("Fragmented IP Packets: %-10lu (%.3f%%)\n", 
                pc.frags, CalcPct((float) pc.frags, recv));
        LogMessage("    Fragment Trackers: %-10lu\n", 
                pc.frag_trackers);
        LogMessage("   Rebuilt IP Packets: %-10lu\n", 
                pc.rebuilt_frags);
        LogMessage("   Frag elements used: %-10lu\n", 
                pc.rebuild_element);
        LogMessage("Discarded(incomplete): %-10lu\n", 
                pc.frag_incomp);
        LogMessage("   Discarded(timeout): %-10lu\n", 
                pc.frag_timeout);
        LogMessage("  Frag2 memory faults: %-10lu\n", 
                pc.frag_mem_faults);
    }

    if(pc.tcp_stream_pkts > 0)
    {
        LogMessage("=============================================="
                "=================================\n");
        LogMessage("TCP Stream Reassembly Stats:\n");
        LogMessage("    TCP Packets Used: %-10lu (%-3.3f%%)\n", 
                pc.tcp_stream_pkts, 
                CalcPct((float) pc.tcp_stream_pkts, recv));
        LogMessage("    Stream Trackers: %-10lu\n", pc.tcp_streams);
        LogMessage("    Stream flushes: %-10lu\n", pc.rebuilt_tcp);
        LogMessage("    Segments used: %-10lu\n", pc.rebuilt_segs);
        LogMessage("    Stream4 Memory Faults: %-10lu\n", 
                pc.str_mem_faults);
    }

    LogMessage("=============================================="
            "=================================\n");

    return;
}


/****************************************************************************
 *
 * Function: InitProtoNames()
 *
 * Purpose: Initializes the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitProtoNames()
{
    int i;
    struct protoent *pt;
    unsigned char *tmp;
    u_char protoname[11];

    for(i = 0; i < 256; i++)
    {
        pt = getprotobynumber(i);

        if(pt)
        {
            protocol_names[i] = strdup(pt->p_name);

            tmp = protocol_names[i];

            for(tmp = protocol_names[i]; *tmp != 0; tmp++)
                *tmp = (unsigned char) toupper(*tmp);
        }
        else
        {
            snprintf(protoname, 10, "PROTO%03d", i);
            protocol_names[i] = strdup(protoname);
        }
    }
}

/****************************************************************************
 *
 * Function: CleanupProtoNames()
 *
 * Purpose: Frees the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanupProtoNames()
{
    int i;

    for(i = 0; i < 256; i++)
    {
        if( protocol_names[i] != NULL )
        {
            free( protocol_names[i] );
            protocol_names[i] = NULL;
        }
    }
}

/****************************************************************************
 *
 * Function: read_infile(char *)
 *
 * Purpose: Reads the BPF filters in from a file.  Ripped from tcpdump.
 *
 * Arguments: fname => the name of the file containing the BPF filters
 *
 * Returns: the processed BPF string
 *
 ****************************************************************************/
char *read_infile(char *fname)
{
    register int fd, cc;
    register char *cp, *cmt;
    struct stat buf;

    fd = open(fname, O_RDONLY);

    if(fd < 0)
        FatalError("can't open %s: %s\n", fname, pcap_strerror(errno));

    if(fstat(fd, &buf) < 0)
        FatalError("can't stat %s: %s\n", fname, pcap_strerror(errno));

    cp = malloc((u_int) buf.st_size + 1);

    cc = read(fd, cp, (int) buf.st_size);

    if(cc < 0)
        FatalError("read %s: %s\n", fname, pcap_strerror(errno));

    if(cc != buf.st_size)
        FatalError("short read %s (%d != %d)\n", fname, cc, (int) buf.st_size);

    cp[(int) buf.st_size] = '\0';

    close(fd);

    /* Treat everything upto the end of the line as a space
     *  so that we can put comments in our BPF filters
     */
    
    while((cmt = strchr(cp, '#')) != NULL)
    {
        while (*cmt != '\r' && *cmt != '\n' && *cmt != '\0')
        {
            *cmt++ = ' ';
        }
    }

    
    return(cp);
}


 /****************************************************************************
  *
  * Function: CheckLogDir()
  *
  * Purpose: CyberPsychotic sez: basically we only check if logdir exist and
  *          writable, since it might screw the whole thing in the middle. Any
  *          other checks could be performed here as well.
  *
  * Arguments: None.
  *
  * Returns: void function
  *
  ****************************************************************************/
void CheckLogDir(void)
{
    struct stat st;
    char log_dir[STD_BUF];

    snprintf(log_dir, STD_BUF, "%s", pv.log_dir);
    stat(log_dir, &st);

    if(!S_ISDIR(st.st_mode) || access(log_dir, W_OK) == -1)
    {
        FatalError("\n[!] ERROR: "
                "Can not get write access to logging directory \"%s\".\n"
                "(directory doesn't exist or permissions are set incorrectly\n"
                /*
                 * let us add this comment. Too many people seem to
                 * confuse it otherwise :-)
                 */
            "or it is not a directory at all)\n\n",
        log_dir);
    }
}


/****************************************************************************
 *
 * Function: GoDaemon()
 *
 * Purpose: Puts the program into daemon mode, nice and quiet like....
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void GoDaemon(void)
{
#ifndef WIN32
    pid_t fs;

    LogMessage("Initializing daemon mode\n");

    if(getppid() != 1)
    {
        fs = fork();

        if(fs > 0)
            exit(0);                /* parent */

        if(fs < 0)
        {
            perror("fork");
            exit(1);
        }
        setsid();
    }
    /* redirect stdin/stdout/stderr to /dev/null */
    close(0);
    close(1);
    close(2);

#ifdef DEBUG
    open("/tmp/snort.debug", O_CREAT | O_RDWR);
#else
    open("/dev/null", O_RDWR);
#endif

    dup(0);
    dup(0);
#endif /* ! WIN32 */
    return;
}


/* This function has been moved into mstring.c, since that
*  is where the allocation actually occurs.  It has been
*  renamed to mSplitFree().
*
void FreeToks(char **toks, int num_toks)
{
    if (toks)
    {
        if (num_toks > 0)
        {
            do
            {
                num_toks--;
                free(toks[num_toks]);
            } while(num_toks);
        }
        free(toks);
    }
}
*/


/* Self preserving memory allocator */
void *SPAlloc(unsigned long size, struct _SPMemControl *spmc)
{
    void *tmp;

    spmc->mem_usage += size;

    if(spmc->mem_usage > spmc->memcap)
    {
        spmc->sp_func(spmc);
    }

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate memory!  (%lu requested, %lu in use)\n",
                size, spmc->mem_usage);
    }

    return tmp;
}


void *SnortAlloc(unsigned long size)
{
    void *tmp;

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate memory!  (%lu requested)\n", size);
    }

    return tmp;
}

/** 
 * Chroot and adjust the pv.log_dir reference 
 * 
 * @param directory directory to chroot to
 * @param logdir ptr to pv.log_dir
 */
void SetChroot(char *directory, char **logstore)
{
#ifdef WIN32
    FatalError("SetChroot() should not be called under Win32!\n");
#else
    char *absdir;
    int abslen;
    char *logdir;
    
    if(!directory || !logstore)
    {
        FatalError("Null parameter passed\n");
    }

    logdir = *logstore;

    if(logdir == NULL || *logdir == '\0')
    {
        FatalError("Null log directory\n");
    }    

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"SetChroot: %s\n",
                                       CurrentWorkingDir()););
    
    logdir = GetAbsolutePath(logdir);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "SetChroot: %s\n",
                                       CurrentWorkingDir()));
    
    logdir = strdup(logdir);

    if(logdir == NULL)
    {
        FatalError("SetChroot: Out of memory");
    }
    
    /* change to the directory */
    if(chdir(directory) != 0)
    {
        FatalError("SetChroot: Can not chdir to \"%s\": %s\n", directory, 
                   strerror(errno));
    }

    /* always returns an absolute pathname */
    absdir = CurrentWorkingDir();

    if(absdir == NULL)                          
    {
        FatalError("NULL Chroot found\n");
    }
    
    abslen = strlen(absdir);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ABS: %s %d\n", absdir, abslen););
    
    /* make the chroot call */
    if(chroot(absdir) < 0)
    {
        FatalError("Can not chroot to \"%s\": absolute: %s: %s\n",
                   directory, absdir, strerror(errno));
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"chroot success (%s ->", absdir););
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"%s)\n ", CurrentWorkingDir()););
    
    /* change to "/" in the new directory */
    if(chdir("/") < 0)
    {
        FatalError("Can not chdir to \"/\" after chroot: %s\n", 
                   strerror(errno));
    }    

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"chdir success (%s)\n",
                            CurrentWorkingDir()););


    if(strncmp(absdir, logdir, strlen(absdir)))
    {
        FatalError("Absdir is not a subset of the logdir");
    }
    
    if(abslen >= strlen(logdir))
    {
        *logstore = "/";
    }
    else
    {
        *logstore = logdir + abslen;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"new logdir from %s to %s\n",
                            logdir, *logstore));

    /* install the I can't do this signal handler */
    signal(SIGHUP, SigCantHupHandler);
#endif /* !WIN32 */
}


/**
 * Return a ptr to the absolute pathname of snort.  This memory must
 * be copied to another region if you wish to save it for later use.
 */
char *CurrentWorkingDir(void)
{
    static char buf[PATH_MAX_UTIL + 1];
    
    if(getcwd((char *) buf, PATH_MAX_UTIL) == NULL)
    {
        return NULL;
    }

    buf[PATH_MAX_UTIL] = '\0';

    return (char *) buf;
}

/**
 * Given a directory name, return a ptr to a static 
 */
char *GetAbsolutePath(char *dir)
{
    char *savedir, *dirp;
    static char buf[PATH_MAX_UTIL + 1];

    if(dir == NULL)
    {
        return NULL;
    }

    savedir = strdup(CurrentWorkingDir());

    if(savedir == NULL)
    {
        return NULL;
    }

    if(chdir(dir) < 0)
    {
        LogMessage("Can't change to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    dirp = CurrentWorkingDir();

    if(dirp == NULL)
    {
        LogMessage("Unable to access current directory\n");
        free(savedir);
        return NULL;
    }
    else
    {
        strncpy(buf, dirp, PATH_MAX_UTIL);
        buf[PATH_MAX_UTIL] = '\0';
    }

    if(chdir(savedir) < 0)
    {
        LogMessage("Can't change back to directory: %s\n", dir);
        free(savedir);                
        return NULL;
    }

    free(savedir);
    return (char *) buf;
}

