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

/* Snort Preprocessor for Telnet Negotiation Normalization*/
/* $Id$ */

/* spp_telnet_negotiation.c 
 * 
 * Purpose:  Telnet and FTP sessions can contain telnet negotiation strings 
 *           that can disrupt pattern matching.  This plugin detects 
 *           negotiation strings in stream and "normalizes" them much like
 *           the http_decode preprocessor normalizes encoded URLs
 *
 *
 * http://www.iana.org/assignments/telnet-options  -- official registry of options
 *
 *
 * Arguments:  None
 *   
 * Effect:  The telnet nogiation data is removed from the payload
 *
 * Comments:
 *
 */

/* your preprocessor header file goes here */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>

#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "log.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"

extern u_int8_t DecodeBuffer[DECODE_BLEN]; /* decode.c */

/* define the telnet negotiation codes (TNC) that we're interested in */
#define TNC_IAC  0xFF
#define TNC_EAC  0xF7
#define TNC_SB   0xFA
#define TNC_NOP  0xF1
#define TNC_SE   0xF0

#define TNC_STD_LENGTH  3

/* list of function prototypes for this preprocessor */
extern void TelNegInit(u_char *);
extern void NormalizeTelnet(Packet *);
static void SetTelnetPorts(char *portlist);
     
/* array containing info about which ports we care about */
static char TelnetDecodePorts[65536/8];



/*
 * Function: SetupTelNeg()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupTelNeg()
{
    /* Telnet negotiation has many names, but we only implement this
     * plugin for Bob Graham's benefit...
     */ 
    RegisterPreprocessor("telnet_decode", TelNegInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: Telnet Decode Decode is setup...\n"););
}


/*
 * Function: TelNegInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void TelNegInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: TelNeg Initialized\n"););

    SetTelnetPorts(args);
    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(NormalizeTelnet);
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
 *
 */
void NormalizeTelnet(Packet *p)
{
    char *read_ptr;
    char *start = (char *) DecodeBuffer; /* decode.c */
    char *write_ptr;
    char *end;
    int normalization_required = 0;

    if(!(p->preprocessors & PP_TELNEG))
    {
        return;
    }
    
    /* check for TCP traffic that's part of an established session */
    if(!PacketIsTCP(p))
    {
        return;
    }

    /* check the port list */
    if(!(TelnetDecodePorts[(p->dp/8)] & (1<<(p->dp%8))))
    {
        return;
    }

    /* negotiation strings are at least 3 bytes long */
    if(p->dsize < TNC_STD_LENGTH)
    {
        return;
    }

    /* setup the pointers */
    read_ptr = p->data;
    end = p->data + p->dsize;
    
    /* look to see if we have any telnet negotiaion codes in the payload */
    while(!normalization_required && (read_ptr < end))
    {
        /* look for the start of a negotiation string */
        if(*read_ptr == (char) TNC_IAC)
        {
            /* set a flag for stage 2 normalization */
            normalization_required = 1;
        }

        read_ptr++;
    }

    if(!normalization_required)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Nothing to process!\n"););
        return;
    }

    /*
     * if we found telnet negotiation strings OR backspace characters,
     * we're going to have to normalize the data
     *
     * Note that this is always ( now: 2002-08-12 ) done to a
     * alternative data buffer.
     */    
    /* rewind the data stream to p->data */
    read_ptr = p->data;
    
    /* setup for overwriting the negotaiation strings with 
     * the follow-on data
     */ 
    write_ptr = (char *) DecodeBuffer;
    
    /* walk thru the remainder of the packet */
    while((read_ptr < end) && (write_ptr < ((char *) DecodeBuffer) + DECODE_BLEN))
    {         
        /* if the following byte isn't a subnegotiation initialization */
        if(((read_ptr + 1) < end) &&
           (*read_ptr == (char) TNC_IAC) &&
           (*(read_ptr + 1) != (char) TNC_SB))
        {
            /* NOPs are two bytes long */
            switch(* ((unsigned char *)(read_ptr + 1)))
            {
            case TNC_NOP:
                read_ptr += 2;
                break;
            case TNC_EAC:
                read_ptr += 2;
                /* wind it back a character */
                if(write_ptr  > start)
                {
                    write_ptr--;
                }
                break;
            default:
                /* move the read ptr up 3 bytes */
                read_ptr += TNC_STD_LENGTH;
            }                
        }
        /* check for subnegotiation */
        else if(((read_ptr + 1) < end) &&
                (*read_ptr == (char) TNC_IAC) &&
                (*(read_ptr+1) == (char) TNC_SB))
        {
            /* move to the end of the subneg */
            do
            {
                read_ptr++;
            } while((*read_ptr != (char) TNC_SE) && (read_ptr < end));
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "overwriting %2X(%c) with %2X(%c)\n",
                                    (char)(*write_ptr&0xFF), *write_ptr, 
                                    (char)(*read_ptr & 0xFF), *read_ptr););
            
            /* overwrite the negotiation bytes with the follow-on bytes */
            *write_ptr++ = *read_ptr++;
        }
    }
    
    p->packet_flags |= PKT_ALT_DECODE;
    
    p->alt_dsize = write_ptr - start;
    
    /* DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "Converted buffer after telnet normalization:\n");
               PrintNetData(stdout, (char *) DecodeBuffer, p->alt_dsize););
    */
}

/*
 * Function: SetTelnetPorts(char *)
 *
 * Purpose: Reads the list of port numbers from the argument string and 
 *          parses them into the port list data struct
 *
 * Arguments: portlist => argument list
 *
 * Returns: void function
 *
 */
static void SetTelnetPorts(char *portlist)
{
    char portstr[STD_BUF];
    char **toks;
    int is_reset = 0;
    int num_toks = 0;
    int num = 0;

    if(portlist == NULL || *portlist == '\0')
    {
        portlist = "21 23 25 119";
    }
    
    /* tokenize the argument list */
    toks = mSplit(portlist, " ", 31, &num_toks, '\\');

    LogMessage("telnet_decode arguments:\n");

    /* convert the tokens and place them into the port list */
    for(num = 0; num < num_toks; num++)
    {
        if(isdigit((int)toks[num][0]))
        {
            char *num_p = NULL; /* used to determine last position in string */
            long t_num;
        
            t_num = strtol(toks[num], &num_p, 10);
        
            if(*num_p != '\0')
            {
                FatalError("Port Number invalid format: %s\n", toks[num]);
            }
            else if(t_num < 0 || t_num > 65335)
            {
                FatalError("Port Number out of range: %ld\n", t_num);
            }
        
            /* user specified a legal port number and it should override the default
               port list, so reset it unless already done */
            if(!is_reset)
            {
                bzero(&TelnetDecodePorts, sizeof(TelnetDecodePorts));
                portstr[0] = '\0';
                is_reset = 1;
            }
        
            /* mark this port as being interesting using some portscan2-type voodoo, 
               and also add it to the port list string while we're at it so we can
               later print out all the ports with a single LogMessage() */
            TelnetDecodePorts[(t_num/8)] |= 1<<(t_num%8);

            if(strlcat(portstr, toks[num], STD_BUF - 1) >= STD_BUF)
            {
                FatalError("%s(%d) Portstr is truncated!\n", file_name, file_line);
            }
                        
            if(strlcat(portstr, " ", STD_BUF - 1) >= STD_BUF)
            {
                FatalError("%s(%d) Portstr is truncated!\n", file_name, file_line);
            }
        }
        else
        {
            FatalError(" %s(%d) => Unknown argument to telnet_decode "
                       "preprocessor: \"%s\"\n", 
                       file_name, file_line, toks[num]);
        }
    }
    
    mSplitFree(&toks, num_toks);

    /* print out final port list */
    LogMessage("    Ports to decode telnet on: %s\n", portstr);
}
