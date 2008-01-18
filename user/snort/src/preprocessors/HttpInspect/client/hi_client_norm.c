/**
**  @file       hi_client_norm.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      HTTP client normalization routines
**  
**  We deal with the normalization of HTTP client requests headers and 
**  URI.
**  
**  In this file, we handle all the different HTTP request URI evasions.  The
**  list is:
**      - ASCII decoding
**      - UTF-8 decoding
**      - IIS Unicode decoding
**      - Directory traversals (self-referential and traversal)
**      - Multiple Slashes
**      - Double decoding
**      - %U decoding
**      - Bare Byte Unicode decoding
**      - Base36 decoding
**  
**  NOTES:
**      - Initial development.  DJR
*/
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

#include "hi_norm.h"
#include "hi_return_codes.h"

#define MAX_URI 4096

static int UriNorm(HI_SESSION *Session)
{
    static u_char UriBuf[MAX_URI];
    HI_CLIENT_REQ    *ClientReq;
    int iRet;
    int iUriBufSize = MAX_URI;
    /*int iCtr;*/

    ClientReq = &Session->client.request;

    if((iRet = hi_norm_uri(Session, UriBuf, &iUriBufSize, ClientReq->uri,
                           ClientReq->uri_size)))
    {
        /*
        **  This means there was a problem while normalizing, so we don't
        **  set anything.
        */
        ClientReq->uri_norm = NULL;
        ClientReq->uri_norm_size = 0;

        /*
        **  We still return successful, and just inspect the unnormalized
        **  URI.
        */
        return HI_SUCCESS;
    }

    /*
    **  This is where we set up the normalized buffer and length.
    */
    ClientReq->uri_norm      = UriBuf;
    ClientReq->uri_norm_size = iUriBufSize;

    /*
    printf("** uri_norm = |");
    for(iCtr = 0; iCtr < ClientReq->uri_norm_size; iCtr++)
    {
        if(!isprint((int)ClientReq->uri_norm[iCtr]))
        {
            printf(".[%.2x]", ClientReq->uri_norm[iCtr]);
            continue;
        }
        printf("%c", ClientReq->uri_norm[iCtr]);
    }
    printf("| size = %u\n", ClientReq->uri_norm_size);
    */

    return HI_SUCCESS;
}

int hi_client_norm(HI_SESSION *Session)
{
    int iRet;

    if(!Session)
    {
        return HI_INVALID_ARG;
    }

    if(!Session->server_conf)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  We only normalize the URI right now.
    **
    **  Make sure that we have a uri to normalize.
    */
    if(Session->client.request.uri_norm)
    {
        if((iRet = UriNorm(Session)))
        {
            return iRet;
        }
    }

    return HI_SUCCESS;
}
