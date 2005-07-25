/* $Id$ */
/*
 * Copyright(C) 2002 Sourcefire, Inc.
 * 
 * Author(s):  Andrew R. Baker <andrewb@snort.org>
 *             Martin Roesch   <roesch@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

/* includes */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "util.h"
#include "mstring.h"
#include "parser.h"

#include "IpAddrSet.h"

void IpAddrSetDestroy(IpAddrSet *ipAddrSet)
{
    IpAddrSet *next;

    while(ipAddrSet)
    {
        next = ipAddrSet->next;
        free(ipAddrSet);
        ipAddrSet = next;
    }
}

static char buffer[1024];

void IpAddrSetPrint(IpAddrSet *ipAddrSet)
{
    struct in_addr in;
    size_t offset = 0;
    while(ipAddrSet)
    {
        offset = 0;
        if(ipAddrSet->addr_flags & EXCEPT_IP)
            offset += snprintf(buffer, 1024 - offset, "NOT ");
        in.s_addr = ipAddrSet->ip_addr;
        offset += snprintf(buffer + offset, 1024 - offset, "%s/", 
                inet_ntoa(in));
        in.s_addr = ipAddrSet->netmask;
        offset += snprintf(buffer + offset, 1024 - offset, "%s", inet_ntoa(in));
        buffer[offset] = '\0';
        LogMessage("%s\n", buffer);
        ipAddrSet = ipAddrSet->next;
    }
}

IpAddrSet *IpAddrSetCopy(IpAddrSet *ipAddrSet)
{
    IpAddrSet *newIpAddrSet = NULL;
    IpAddrSet *current = NULL;
    IpAddrSet *prev = NULL;

    while(ipAddrSet)
    {
        if(!(current = (IpAddrSet *)malloc(sizeof(IpAddrSet))))
        {
            /* ENOMEM */
            goto failed;
        }
        
        current->ip_addr = ipAddrSet->ip_addr;
        current->netmask = ipAddrSet->netmask;
        current->addr_flags = ipAddrSet->addr_flags;
        current->next = NULL;

        if(!prev)
            newIpAddrSet = current;
        else
            prev->next = current;

        ipAddrSet = ipAddrSet->next;
        prev = current;
    }

    return newIpAddrSet;

failed:
    if(newIpAddrSet)
        IpAddrSetDestroy(newIpAddrSet);
    return NULL; /* XXX ENOMEM */
}


/* XXX: legacy support function */
/*
 * Function: ParseIP(char *, IpAddrSet *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
 *          value.  Also convert the CIDR block notation into a real
 *          netmask.
 *
 * Arguments: char *addr  => address string to convert
 *            IpAddrSet * =>
 *            
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 */
int ParseIP(char *paddr, IpAddrSet *address_data)
{
    char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by mSplit() */
    int cidr = 1;       /* is network expressed in CIDR format */
    int nmask;          /* netmask temporary storage */
    char *addr;         /* string to parse, eventually a
                         * variable-contents */
    struct hostent *host_info;  /* various struct pointers for stuff */
    struct sockaddr_in sin; /* addr struct */

    addr = paddr;

    if(*addr == '!')
    {
        address_data->addr_flags |= EXCEPT_IP;

        addr++;  /* inc past the '!' */
    }

    /* check for wildcards */
    if(!strcasecmp(addr, "any"))
    {
        address_data->ip_addr = 0;
        address_data->netmask = 0;
        return 1;
    }
    /* break out the CIDR notation from the IP address */
    toks = mSplit(addr, "/", 2, &num_toks, 0);

    /* "/" was not used as a delimeter, try ":" */
    if(num_toks == 1)
    {
        mSplitFree(&toks, num_toks);
        toks = mSplit(addr, ":", 2, &num_toks, 0);
    }

    /*
     * if we have a mask spec and it is more than two characters long, assume
     * it is netmask format
     */
    if((num_toks > 1) && strlen(toks[1]) > 2)
    {
        cidr = 0;
    }

    switch(num_toks)
    {
        case 1:
            address_data->netmask = netmasks[32];
            break;

        case 2:
            if(cidr)
            {
                /* convert the CIDR notation into a real live netmask */
                nmask = atoi(toks[1]);

                /* it's pain to differ whether toks[1] is correct if netmask */
                /* is /0, so we deploy some sort of evil hack with isdigit */

                if(!isdigit((int) toks[1][0]))
                    nmask = -1;

                if((nmask > -1) && (nmask < 33))
                {
                    address_data->netmask = netmasks[nmask];
                }
                else
                {
                    FatalError("ERROR %s(%d): Invalid CIDR block for IP addr "
                            "%s\n", file_name, file_line, addr);
                           
                }
            }
            else
            {
                /* convert the netmask into its 32-bit value */

                /* broadcast address fix from 
                 * Steve Beaty <beaty@emess.mscd.edu> 
                 */

                /*
                 * if the address is the (v4) broadcast address, inet_addr *
                 * returns -1 which usually signifies an error, but in the *
                 * broadcast address case, is correct.  we'd use inet_aton() *
                 * here, but it's less portable.
                 */
                if(!strncmp(toks[1], "255.255.255.255", 15))
                {
                    address_data->netmask = INADDR_BROADCAST;
                }
                else if((address_data->netmask = inet_addr(toks[1])) == -1)
                {
                    FatalError("ERROR %s(%d): Unable to parse rule netmask "
                            "(%s)\n", file_name, file_line, toks[1]);
                }
            }
            break;

        default:
            FatalError("ERROR %s(%d) => Unrecognized IP address/netmask %s\n",
                    file_name, file_line, addr);
            break;
    }
#ifndef WORDS_BIGENDIAN
    /*
     * since PC's store things the "wrong" way, shuffle the bytes into the
     * right order.  Non-CIDR netmasks are already correct.
     */
    if(cidr)
    {
        address_data->netmask = htonl(address_data->netmask);
    }
#endif

    /* convert names to IP addrs */
    if(isalpha((int) toks[0][0]))
    {
        /* get the hostname and fill in the host_info struct */
        if((host_info = gethostbyname(toks[0])))
        {
            /* protecting against malicious DNS servers */
            if(host_info->h_length <= sizeof(sin.sin_addr))
            {
                bcopy(host_info->h_addr, (char *) &sin.sin_addr, host_info->h_length);
            }
            else
            {
                bcopy(host_info->h_addr, (char *) &sin.sin_addr, sizeof(sin.sin_addr));
            }
        }
        else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE)
        {
            FatalError("ERROR %s(%d): Couldn't resolve hostname %s\n",
                    file_name, file_line, toks[0]);
        }

        address_data->ip_addr = ((u_long) (sin.sin_addr.s_addr) &
                                 (address_data->netmask));
        mSplitFree(&toks, num_toks);
        return 1;
    }

    /* convert the IP addr into its 32-bit value */

    /* broadcast address fix from Steve Beaty <beaty@emess.mscd.edu> */

    /*
     * if the address is the (v4) broadcast address, inet_addr returns -1 *
     * which usually signifies an error, but in the broadcast address case, *
     * is correct.  we'd use inet_aton() here, but it's less portable.
     */
    if(!strncmp(toks[0], "255.255.255.255", 15))
    {
        address_data->ip_addr = INADDR_BROADCAST;
    }
    else if((address_data->ip_addr = inet_addr(toks[0])) == -1)
    {
        FatalError("ERROR %s(%d): Rule IP addr (%s) didn't translate\n", 
                file_name, file_line, toks[0]);
    }
    else
    {
        /* set the final homenet address up */
        address_data->ip_addr = ((u_long) (address_data->ip_addr) &
                (address_data->netmask));
    }

    mSplitFree(&toks, num_toks);

    return 0;
}                                                                                            

