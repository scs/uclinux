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
/* Snort Preprocessor Plugin Source File Bo */

/* spp_bo 
 * 
 * Purpose: Detects Back Orifice traffic by brute forcing the weak encryption
 *          of the program's network protocol and detects the magic cookie
 *          that it's servers and clients require to communicate with each 
 *          other.
 *
 * Arguments: none
 *   
 * Effect: Analyzes UDP traffic for the BO magic cookie, reports if it finds
 *         traffic matching the profile.
 *
 * Comments:
 *
 */

/*
 * The following text describes a couple of ways in which the Back Orifice
 * signature is calculated.  The snort runtime generated an array of 65K
 * possible signatures, of which two are described here.  Refer back to
 * this simplified algorithm when evaluating the snort code below.
 *
 * Back Orifice magic cookie is "*!*QWTY?", which is located in the first
 * eight bytes of the packet.  But it is encrypted using an XOR.  Here we'll
 * generate a sequence of eight bytes which will decrypt (XOR) into the
 * magic cookie.  This test uses the NON-DEFAULT KEY to initialize (seed) the
 * "random" number generator.  The default seed results in the following
 * sequence of bytes:  E4 42 FB 83 41 B3 4A F0.  When XOR'd against the
 * magic cookie, we have our packet data which looks like a Back Orifice
 * signature:
 *
 *   Cookie:  2A 21 2A 51 57 54 59 3F
 *   Random:  E4 42 FB 83 41 B3 4A F0
 *   -------  -- -- -- -- -- -- -- --
 *   Result:  CE 63 D1 D2 16 E7 13 CF  (XOR'd result)
 * 
 * For demonstration purposes:
 *
 *   static long holdrand = 1L;
 *   static int LocalBoRand()
 *   {
 *       return(((holdrand = holdrand * 214013L + 2531011L) >> 16) & 0x7fff);
 *   }
 *   ...
 *
 *   int BoRandValues_NonDefaultKey[8];
 *   holdrand = BACKORIFICE_DEFAULT_KEY;    (seed value)
 *   BoRandValues_NonDefaultKey[0] = LocalBoRand() % 256;  --> 228 (0xe4)
 *   BoRandValues_NonDefaultKey[1] = LocalBoRand() % 256;  -->  66 (0x42)
 *   BoRandValues_NonDefaultKey[2] = LocalBoRand() % 256;  --> 251 (0xfb)
 *   BoRandValues_NonDefaultKey[3] = LocalBoRand() % 256;  --> 131 (0x83)
 *   BoRandValues_NonDefaultKey[4] = LocalBoRand() % 256;  -->  65 (0x41)
 *   BoRandValues_NonDefaultKey[5] = LocalBoRand() % 256;  --> 179 (0xb3)
 *   BoRandValues_NonDefaultKey[6] = LocalBoRand() % 256;  -->  74 (0x4a)
 *   BoRandValues_NonDefaultKey[7] = LocalBoRand() % 256;  --> 240 (0xf0)
 *
 *
 * The following test uses the DEFAULT KEY to initialize (seed) the
 * "random" number generator.  The default seed results in the following
 * sequence of bytes:  26 27 F6 85 97 15 AD 1D.  When XOR'd against the
 * magic cookie, we have our packet data which looks like a Back Orifice
 * signature:
 *
 *   Cookie:  2A 21 2A 51 57 54 59 3F
 *   Random:  26 27 F6 85 97 15 AD 1D
 *   -------  -- -- -- -- -- -- -- --
 *   Result:  0C 06 DC D4 C0 41 F4 22  (XOR'd result)
 * 
 * For demonstration purposes:
 *
 *   int BoRandValues_DefaultKey[8];
 *   holdrand = 0;    (seed value)
 *   BoRandValues_DefaultKey[0] = LocalBoRand() % 256;  -->  38 (0x26)
 *   BoRandValues_DefaultKey[1] = LocalBoRand() % 256;  -->  39 (0x27)
 *   BoRandValues_DefaultKey[2] = LocalBoRand() % 256;  --> 246 (0xf6)
 *   BoRandValues_DefaultKey[3] = LocalBoRand() % 256;  --> 133 (0x85)
 *   BoRandValues_DefaultKey[4] = LocalBoRand() % 256;  --> 151 (0x97)
 *   BoRandValues_DefaultKey[5] = LocalBoRand() % 256;  -->  21 (0x15)
 *   BoRandValues_DefaultKey[6] = LocalBoRand() % 256;  --> 173 (0xad)
 *   BoRandValues_DefaultKey[7] = LocalBoRand() % 256;  -->  29 (0x1d)
 * 
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "generators.h"
#include "log.h"
#include "detect.h"
#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "util.h"
#include "event_queue.h"

#include "snort.h"

#define BACKORIFICE_DEFAULT_KEY  31337
#define BACKORIFICE_MAGIC_SIZE   8
#define BACKORIFICE_MIN_SIZE   18

/* list of function prototypes for this preprocessor */
void BoInit(u_char *);
void ParseBoArgs(char *);
void BoProcess(Packet *);
void PrecalcPrefix();
void BoFind(Packet *);

#define MODNAME "spp_bo"

int BoRand();
void ParseBoArgs(char *);

/* global keyvalue for the BoRand() function */
static long holdrand = 1L;

/* brute forcing is on by default */
int brute_force_enable = 1;
int default_key;

u_int16_t lookup1[65536][3];
u_int16_t lookup2[65536];

/*
 * Function: SetupBo()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupBo()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterPreprocessor("bo", BoInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                "Preprocessor: Back Orifice is setup...\n"););
}


/*
 * Function: BoInit(u_char *)
 *
 * Purpose: Link the BO preprocessor to the preperocessor call chain.
 *
 * Arguments: args => ptr to argument string (spp_bo takes no args)
 *
 * Returns: void function
 *
 */
void BoInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: Bo Initialized\n"););

    /* we no longer need to take args */
    PrecalcPrefix();

    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(BoFind);
}


/*
 * Function: BoRand()
 *
 * Purpose: Back Orifice "encryption" algorithm
 *
 * Arguments: None.
 *
 * Returns: key to XOR with current char to be "encrypted"
 */
int BoRand()
{
    return(((holdrand = holdrand * 214013L + 2531011L) >> 16) & 0x7fff);
}


/*
 * Precalculate the known cyphertext into a prefix and suffix lookup table 
 * to recover the key.  Using this in the BoFind() function below is much
 * faster than the old brute force method
 */
void PrecalcPrefix()
{
    u_int8_t cookie_cyphertext[BACKORIFICE_MAGIC_SIZE];
    char *cookie_plaintext = "*!*QWTY?";
    int key;
    int cookie_index;
    char *cp_ptr;       /* cookie plaintext indexing pointer */
    u_int16_t cyphertext_referent;
    
    for(key=0;key<65536;key++)
    {
        /* setup to generate cyphertext for this key */
        holdrand = key;
        cp_ptr = cookie_plaintext;

        /* convert the plaintext cookie to cyphertext for this key */
        for(cookie_index=0;cookie_index<BACKORIFICE_MAGIC_SIZE;cookie_index++)
        {
            cookie_cyphertext[cookie_index] =(u_int8_t)(*cp_ptr^(BoRand()%256));
            cp_ptr++;
        }

        /* 
         * generate the key lookup mechanism from the first 2 characters of
         * the cyphertext
         */
        cyphertext_referent = (u_int16_t) (cookie_cyphertext[0] << 8) & 0xFF00;
        cyphertext_referent |= (u_int16_t) (cookie_cyphertext[1]) & 0x00FF;

        /* if there are any keyspace collisions that's going to suck */
        if(lookup1[cyphertext_referent][0] != 0)
        {
            if(lookup1[cyphertext_referent][1] != 0)
            {
                lookup1[cyphertext_referent][2] = key;
            }
            else
            {
                lookup1[cyphertext_referent][1] = key;
            }
        }
        else
        {
            lookup1[cyphertext_referent][0] = key;
        }

        /* 
         * generate the second lookup from the last two characters of 
         * the cyphertext
         */
        cyphertext_referent = (u_int16_t) (cookie_cyphertext[6] << 8) & 0xFF00;
        cyphertext_referent |= (u_int16_t) (cookie_cyphertext[7]) & 0x00FF;

        /*
         * set the second lookup with the current key
         */
        lookup2[key] = cyphertext_referent;
    }
}


/*
 * Function: BoFind(Packet *)
 *
 * Purpose: Look for the magic cookie, squawk if you find it.
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void BoFind(Packet *p)
{
    u_int16_t cyphertext_referent;
    u_int16_t cyphertext_suffix;
    u_int16_t key;
    char *magic_cookie = "*!*QWTY?";
    char *pkt_data;
    char *magic_data;
    char *end;
    char plaintext;
    char outstring[STD_BUF];
    int i;


    if(!(p->preprocessors & PP_BO))
    {
        return;
    }
    
    /* make sure it's UDP and that it's at least 19 bytes long */
    if(!PacketIsUDP(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                    "   -> spp_bo: Not UDP\n"););
        return;
    }

    if(p->dsize < BACKORIFICE_MIN_SIZE)
    {
        return;
    }

    /*
     * take the first two characters of the packet and generate the 
     * first reference that gives us a reference key
     */
    cyphertext_referent = (u_int16_t) (p->data[0] << 8) & 0xFF00;
    cyphertext_referent |= (u_int16_t) (p->data[1]) & 0x00FF;

    /* 
     * generate the second referent from the last two characters
     * of the cyphertext
     */
    cyphertext_suffix = (u_int16_t) (p->data[6] << 8) & 0xFF00;
    cyphertext_suffix |= (u_int16_t) (p->data[7]) & 0x00FF;

    for(i=0;i<3;i++)
    {
        /* get the key from the cyphertext */
        key = lookup1[cyphertext_referent][i];

        /* 
         * if the lookup from the proposed key matches the cyphertext reference
         * then we've probably go the right key and can proceed to full 
         * decryption using the key
         *
         * moral of the story: don't use a lame keyspace 
         */
        if(lookup2[key] == cyphertext_suffix)
        {
            holdrand = key;
            pkt_data = p->data;
            end = p->data + BACKORIFICE_MAGIC_SIZE;
            magic_data = magic_cookie;

            while(pkt_data<end)
            {
                plaintext = (char) (*pkt_data ^ (BoRand()%256));

                if(*magic_data != plaintext)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "Failed check one on 0x%X : 0x%X\n", 
                            *magic_data, plaintext););
                    return;
                }

                magic_data++;
                pkt_data++;
            }

            /* if we fall thru there's a detect */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                        "Detected Back Orifice Data!\n");
            DebugMessage(DEBUG_PLUGIN, "hash value: %d\n", key););
            snprintf(outstring, STD_BUF-1, 
                    "spp_bo: Back Orifice Traffic detected (key: %d)", key);
            
            SnortEventqAdd(GENERATOR_SPP_BO, BO_TRAFFIC_DETECT, 1, 0, 0,
                    BO_TRAFFIC_DETECT_STR, 0);
        }
    }

    return;
}
