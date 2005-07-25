

/* x-link2state 
 * 
 * Copyright (C) 2005 Sourcefire,Inc.
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>
#include <string.h>

/*
 * If you're going to issue any alerts from this preproc you 
 * should include generators.h and event_wrapper.h
 */
#include "generators.h"
#include "event_wrapper.h"
#include "event_queue.h"

#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "snort.h"

/* In case we need to drop this packet */
#include "inline.h"

/* Okay, we may need to threshold this crap, too */
#include "sfthreshold.h"

/*
 * put in other includes as necessary
 */
#include "debug.h"

#include "str_search.h"
#include "xlink2state.h"

/* Pointer to current session data */
XLINK2STATE *_xlink;
static u_int       _xlink2state_ports[65535];
static u_int       _xlink2state_disabled = 0;
static u_int       _xlink2state_drop = 0;
static Packet      *_xlink2state_pkt = NULL;

/*
**  Port list delimiters
*/
#define START_LIST      "{"
#define END_LIST        "}"
#define PORTS           "ports"
#define DISABLE         "disable"
#define INLINE_DROP     "drop"
#define CONF_SEPARATORS " \t\n\r"

#define ERRSTRLEN   512

/*
 * Initialize SMTP preprocessor
 *
 * @param  none
 *
 * @return none
 */
void XLINK2STATE_Init(void)
{
    /*  Set up commands we will watch for */
    SearchInit(1);
    
    /*  Set up commands we will watch for */
    SearchInit(1);
    
    SearchAdd(0, "X-LINK2STATE", 0);
    
    SearchPrepPatterns(0);

}


/*
 * Free XLINK2STATE-specific related to this session
 *
 * @param   v   pointer to XLINK2STATE session structure
 *
 * @return  none
 */
void XLINK2STATE_SessionFree(void * v)
{
    XLINK2STATE *x = (XLINK2STATE *) v;

    if ( x )
        free(x);
    return;
}


/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static void XLINK2STATE_Setup(Packet *p)
{
    Session      *ssnptr;

    /*  Get session pointer */
    ssnptr = (Session *) (p->ssnptr);

    if ( ssnptr && ssnptr->preproc_data == NULL )
    {
        XLINK2STATE *x = (XLINK2STATE *) malloc(sizeof(XLINK2STATE));
        if ( x == NULL )
        {
            FatalError("%s(%d) => Failed to allocate for X-Link2State session data\n", 
                    file_name, file_line);
            return;
        }
        memset(x, 0, sizeof(XLINK2STATE));
        ssnptr->preproc_data = x;
        ssnptr->preproc_free = XLINK2STATE_SessionFree;
    }
}

/*
 * Given a server configuration and a port number, we decide if the port is
 *  in the SMTP server port list.
 *
 *  @param  port       the port number to compare with the configuration
 *
 *  @return integer
 *  @retval  0 means that the port is not a server port
 *  @retval !0 means that the port is a server port
 */
static int IsServer(unsigned short port)
{
    if( _xlink2state_ports[port] )
    {
        return 1;
    }

    return 0;
}

int axtoi(char *hexStg) {
  int n = 0;         // position in string
  int m = 0;         // position in digit[] to shift
  int count;         // loop index
  int intValue = 0;  // integer value of hex string
  int digit[8];      // hold values to convert
  while (n < 8) {
     if (hexStg[n]=='\0')
        break;
     if (hexStg[n] > 0x29 && hexStg[n] < 0x40 ) //if 0 to 9
        digit[n] = hexStg[n] & 0x0f;            //convert to int
     else if (hexStg[n] >='a' && hexStg[n] <= 'f') //if a to f
        digit[n] = (hexStg[n] & 0x0f) + 9;      //convert to int
     else if (hexStg[n] >='A' && hexStg[n] <= 'F') //if A to F
        digit[n] = (hexStg[n] & 0x0f) + 9;      //convert to int
     else break;
    n++;
  }
  count = n;
  m = n - 1;
  n = 0;
  while(n < count) {
     // digit[n] is value of hex digit at position n
     // (m << 2) is the number of positions to shift
     // OR the bits into return value
     intValue = intValue | (digit[n] << (m << 2));
     m--;   // adjust the position to set
     n++;   // next digit to process
  }
  return (intValue);
}

static char * safe_strchr(char *buf, char c, u_int len)
{
    char *p = buf;
    int i = 0;

    while ( i < len )
    {
        if ( *p == c )
        {
            return p;
        }
        i++;
        p++;
    }

    return NULL;
}

int ParseXLink2State(int id, u_int8_t *x)
{
    char *eq;
    char *start;
    char *lf;
    int   len = 0;
    u_int x_len;

    /* Calculate length from pointer to end of packet data */
    x_len = _xlink2state_pkt->dsize - (x - _xlink2state_pkt->data);

    eq = safe_strchr(x, '=', x_len);
    if ( !eq )
        return 0;

    /*  Look for one of two patterns:

        ... CHUNK={0000006d} MULTI (5) ({00000000051} ...
        ... CHUNK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n
     */
    if ( *(eq+1) == '{' )
    {
        /* Parse length - can we always trust it? */
        start = eq + 2;
        len = axtoi(start);
#if 0
        start = safe_strchr(eq, '}', x_len);
        if ( !start )
            return 0;
        start++;
        while ( isspace(*start) )
            start++;
        /* start should point at "MULTI" now */
#endif
    }
    else
    {
        start = eq + 1;
    }

    if ( len == 0 )
    {
        lf = safe_strchr(x, '\n', x_len);
        if ( !lf )
            return 0;

        len = lf - start;
    }
    _xlink->length += len;

    if ( _xlink->length > 1024 )
    {
        /* Need to drop the packet if we're told to
         * and we're inline mode (outside of whether its
         * thresholded). */
        if (_xlink2state_drop && InlineMode())
        {
            _xlink2state_pkt->packet_flags |= PKT_INLINE_DROP; 
            InlineDrop();
        }

        /* Are we thresholding this event? */
        if( !sfthreshold_test( GENERATOR_SMTP,
                               1,
                               _xlink2state_pkt->iph->ip_src.s_addr,
                               _xlink2state_pkt->iph->ip_dst.s_addr,
                               _xlink2state_pkt->pkth->ts.tv_sec) )
        {
            _xlink->alerted = 1;
            return 1;
        }

        SnortEventqAdd(GENERATOR_SMTP, 1, 1, 0, 3, "X-Link2State length greater than 1024", 0);
        _xlink->alerted = 1;

        return 1;
    }

    return 0;
}

/*
 * Callback function from search
 *
 * @param   id      id in array of search strings from _smtp_config.cmds
 * @param   index   index in array of search strings from _smtp_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
int StrFound(void *id, int index, void *data)
{
    int  iid = (int) id;
    u_int8_t *buf = (char *) data;
    u_int8_t *ptr = buf + index;
    
    /* Found X-LINK2STATE, parse lengths */

    /* Returning zero tells search engine to keep sending matches */
    return ParseXLink2State(iid, ptr);
}

/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void XLINK2STATE_ProcessPacket(Packet *p)
{
    int  strFound;
    Session *ssnptr = NULL;

    if(!p->ssnptr)
    {
        return;
    }
    ssnptr = (Session *)p->ssnptr;

    _xlink = (XLINK2STATE *) ssnptr->preproc_data;

    /* Save the packet pointer, so we can set the
     * packet's drop flags and check for thresholding. */
    _xlink2state_pkt = p;

    /* Only need to alert once per session */
    if ( _xlink->alerted )
    {
        if (_xlink2state_drop && InlineMode())
        {
            _xlink2state_pkt->packet_flags |= PKT_INLINE_DROP; 
            InlineDrop();
        }
        return;
    }

    /*  Check for X-LINK2STATE string */
    strFound = SearchFindString(0, p->data, p->dsize, StrFound);

}

/*
 * Entry point to snort preprocessor for each packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
void SnortXLINK2STATE(Packet *p)
{
    /* See if we are disabled */
    if ( _xlink2state_disabled )
        return;

    /*  Make sure it's traffic we're interested in
        Only client traffic for X-LINK2STATE */
    if ( !IsServer(p->dp) )
        return;

       /*  Ignore if not enough data */
    if (p->dsize < 18)
        return;
    
    XLINK2STATE_Setup(p);
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, " <SMTP packet from client>\n"););

    if (p->packet_flags & PKT_STREAM_INSERT)
    {
        /* Packet will be rebuilt, so wait for it */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Client packet will be reassembled\n"));
        return;
    }
   
    /* Process as a client packet */
    XLINK2STATE_ProcessPacket(p);
}



static int PrintConfig(void)
{
    int i;
    char buf[STD_BUF+1];

    LogMessage("X-Link2State Config:\n");
    
    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Ports: ");
    for(i = 0; i < 65536; i++)
    {
        if(_xlink2state_ports[i])
        {
            sfsnprintfappend(buf, STD_BUF, "%d ", i);
        }
    }
    LogMessage("%s\n", buf);
    if (InlineMode())
        LogMessage("    Drop Packets (inline only): %s\n", _xlink2state_drop ? "YES" : "NO");
    
    return 0;
}


/*
**  NAME
**    ProcessPorts::
**
**  Process the port list.
**
**  This configuration is a list of valid ports and is ended by a 
**  delimiter.
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessPorts(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iPort;
    int  iEndPorts = 0;

    /*  Clear out default port */
    _xlink2state_ports[SMTP_DEFAULT_SERVER_PORT] = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid port list format.");

        return -1;
    }

    if(strcmp(START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a port list with the '%s' token.",
                START_LIST);

        return -1;
    }
    
    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_LIST, pcToken))
        {
            iEndPorts = 1;
            break;
        }

        iPort = strtol(pcToken, &pcEnd, 10);

        /*
        **  Validity check for port
        */
        if(*pcEnd)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid port number.");

            return -1;
        }

        if(iPort < 0 || iPort > 65535)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid port number.  Must be between 0 and "
                    "65535.");

            return -1;
        }

        _xlink2state_ports[iPort] = 1;
    }

    if(!iEndPorts)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end '%s' configuration with '%s'.",
                PORTS, END_LIST);

        return -1;
    }

    return 0;
}

/*
 * Function: XLINK2STATE_ParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguments from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
void XLINK2STATE_ParseArgs(u_char *args)
{
    int   ret = 0;
    char *arg;
    char errStr[ERRSTRLEN];
    int  errStrLen = ERRSTRLEN;
    
    _xlink2state_ports[SMTP_DEFAULT_SERVER_PORT] = 1;

    if ( args == NULL )
    {
        return;
    }

    arg = strtok(args, CONF_SEPARATORS);
    
    while ( arg != NULL )
    {
        if ( !strcasecmp(PORTS, arg) )
        {
            ret = ProcessPorts(errStr, errStrLen);
            if ( ret == -1 )
                break;
        }
        else if ( !strcasecmp(DISABLE, arg) )
        {
            _xlink2state_disabled = 1;
        }
        else if ( !strcasecmp(INLINE_DROP, arg) )
        {
            if (InlineMode())
                _xlink2state_drop = 1;
            else
                LogMessage("%s(%d) WARNING: drop keyword ignored."
                           "snort is not in inline mode\n",
                           file_name, file_line);
        }

        /*  Get next token */
        arg = strtok(NULL, CONF_SEPARATORS);
    }

    if ( ret < 0 )
    {
        /*
        **  Fatal Error, log error and exit.
        */
        if(*errStr)
        {
            FatalError("%s(%d) => %s\n", 
                    file_name, file_line, errStr);
        }
        else
        {
            FatalError("%s(%d) => Undefined Error.\n", 
                        file_name, file_line);
        }
    }

    PrintConfig();
}

