/* $Id$ */

/**
**  @file        sp_asn1.c
**
**  @author      Daniel Roelker <droelker@sourcefire.com>
** 
**  @brief       Decode and detect ASN.1 types, lengths, and data.
**
**  Copyright (C) 2004, Daniel Roelker and Sourcefire, Inc.
**
**  This detection plugin adds ASN.1 detection functions on a per rule
**  basis.  ASN.1 detection plugins can be added by editing this file and
**  providing an interface in the configuration code.
**  
**  Detection Plugin Interface:
**
**  asn1: [detection function],[arguments],[offset type],[size]
**
**  Detection Functions:
**
**  bitstring_overflow: no arguments
**  double_overflow:    no arguments
**  oversize_length:    max size (if no max size, then just return value)
**
**  alert udp any any -> any 161 (msg:"foo"; \
**      asn1: oversize_length 10000, absolute_offset 0;)
**
**  alert tcp any any -> any 162 (msg:"foo2"; \
**      asn1: bitstring_overflow, oversize_length 500, relative_offset 7;)
**
**
**  Note that further general information about ASN.1 can be found in
**  the file doc/README.asn1.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "bounds.h"
#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "asn1.h"

#define BITSTRING_OPT  "bitstring_overflow"
#define DOUBLE_OPT     "double_overflow"
#define LENGTH_OPT     "oversize_length"
#define DBL_FREE_OPT   "double_free"

#define ABS_OFFSET_OPT "absolute_offset"
#define REL_OFFSET_OPT "relative_offset"
#define PRINT_OPT      "print"

#define ABS_OFFSET 1
#define REL_OFFSET 2

#define DELIMITERS " ,\t\n"

typedef struct s_ASN1_CTXT
{
    int bs_overflow;
    
    int double_overflow;

    int print;

    int length;
    unsigned int max_length;

    int offset;
    int offset_type;

} ASN1_CTXT;

extern u_int8_t *doe_ptr;

/*
**  NAME
**    Asn1RuleParse::
*/
/**
**  Parse the detection option arguments.
**    - bitstring_overflow
**    - double_overflow
**    - oversize_length
**    - print
**    - abs_offset
**    - rel_offset
**
**  @return void
*/
static void Asn1RuleParse(char *data, OptTreeNode *otn, ASN1_CTXT *asn1)
{
    char *pcTok;

    if(!data)
    {
        FatalError("%s(%d) => No options to 'asn1' detection plugin.\n",
                   file_name, file_line);
    }

    pcTok = strtok(data, DELIMITERS);
    if(!pcTok)
    {
        FatalError("%s(%d) => No options to 'asn1' detection plugin.\n",
                   file_name, file_line);
    }

    while(pcTok)
    {
        if(!strcasecmp(pcTok, BITSTRING_OPT))
        {
            asn1->bs_overflow = 1;
        }
        else if(!strcasecmp(pcTok, DOUBLE_OPT))
        {
            asn1->double_overflow = 1;
        }
        else if(!strcasecmp(pcTok, PRINT_OPT))
        {
            asn1->print = 1;
        }
        else if(!strcasecmp(pcTok, LENGTH_OPT))
        {
            pcTok = strtok(NULL, DELIMITERS);
            if(!pcTok)
            {
                FatalError("%s(%d) => No option to '%s' in 'asn1' detection "
                           "plugin\n", LENGTH_OPT, file_name, file_line);
            }

            asn1->length = 1;
            asn1->max_length = atoi(pcTok);

            if(asn1->max_length < 0)
            {
                FatalError("%s(%d) => Negative size to '%s' in 'asn1' "
                           "detection plugin.  Must be positive or zero.\n", 
                           LENGTH_OPT, file_name, file_line);
            }
        }
        else if(!strcasecmp(pcTok, ABS_OFFSET_OPT))
        {
            pcTok = strtok(NULL, DELIMITERS);
            if(!pcTok)
            {
                FatalError("%s(%d) => No option to '%s' in 'asn1' detection "
                           "plugin\n", ABS_OFFSET_OPT, file_name, file_line);
            }

            asn1->offset_type = ABS_OFFSET;
            asn1->offset = atoi(pcTok);
        }
        else if(!strcasecmp(pcTok, REL_OFFSET_OPT))
        {
            pcTok = strtok(NULL, DELIMITERS);
            if(!pcTok)
            {
                FatalError("%s(%d) => No option to '%s' in 'asn1' detection "
                           "plugin\n", REL_OFFSET_OPT, file_name, file_line);
            }

            asn1->offset_type = REL_OFFSET;
            asn1->offset = atoi(pcTok);
        }
        else
        {
            FatalError("%s(%d) => Unknown ('%s') asn1 detection option.\n",
                       file_name, file_line, pcTok);
        }

        pcTok = strtok(NULL, DELIMITERS);
    }

    return;
}

/*
**  NAME
**    BitStringOverflow::
*/
/**
**  The neccessary info to detect possible bitstring overflows.  Thanks
**  once again to microsoft for keeping us in business.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int BitStringOverflow(ASN1_TYPE *asn1, void * user)
{
    if(!asn1)
        return 0;

    /*
    **  Here's what this means:
    **
    **  If the ASN.1 type is a non-constructed bitstring (meaning that
    **  there is only one encoding, not multiple encodings).  And
    **  the number of bits to ignore (this is taken from the first byte)
    **  is greater than the total number of bits, then we have an
    **  exploit attempt.
    */
    if(asn1->ident.tag == SF_ASN1_TAG_BIT_STR && !asn1->ident.flag)
    {
        if(asn1->len.size && asn1->data && 
           (((asn1->len.size - 1)<<3) < (unsigned int)asn1->data[0]))
        {
            return 1;
        }
    }

    return 0;
}

/*
**  NAME
**    DetectBitStringOverflow::
*/
/**
**  This is just a wrapper to the traverse function.  It's important because
**  this allows us to do more with individual nodes in the future.
**
**  @return integer
**
**  @retval 0 failed
**  @rteval 1 detected
*/
static int DetectBitStringOverflow(ASN1_TYPE *asn1)
{
    return asn1_traverse(asn1, NULL, BitStringOverflow);
}

/*
**  NAME
**    DoubleOverflow::
*/
/**
**  This is the info to detect double overflows.  This may not be a
**  remotely exploitable (remote services may not call the vulnerable
**  microsoft function), but better safe than sorry.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int DoubleOverflow(ASN1_TYPE *asn1, void *user)
{
    if(!asn1)
        return 0;

    /*
    **  Here's what this does.
    **
    **  There is a vulnerablity in the MSASN1 library when decoding
    **  a double (real) type.  If the encoding is ASCII (specified by
    **  not setting bit 7 or 8), and the buffer is greater than 256,
    **  then you overflow the array in the function.
    */
    if(asn1->ident.tag == SF_ASN1_TAG_REAL && !asn1->ident.flag)
    {
        if(asn1->len.size && asn1->data &&
           ((asn1->data[0] & 0xc0) == 0x00) && 
           (asn1->len.size > 256))
        {
            return 1;
        }
    }

    return 0;
}

/*
**  NAME
**    DetectDoubleOverflow::
*/
/**
**  This is just a wrapper to the traverse function.  It's important because
**  this allows us to do more with individual nodes in the future.
**
**  @return integer
**
**  @retval 0 failed
**  @rteval 1 detected
*/
static int DetectDoubleOverflow(ASN1_TYPE *asn1)
{
    return asn1_traverse(asn1, NULL, DoubleOverflow);
}

/*
**  NAME
**    OversizeLength::
*/
/**
**  This is the most generic of our ASN.1 detection functionalities.  This
**  will compare the ASN.1 type lengths against the user defined max
**  length and alert if the length is greater than the user supplied length.
**  
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int OversizeLength(ASN1_TYPE *asn1, void *user)
{
    unsigned int *max_size;

    if(!asn1 || !user)
        return 0;

    max_size = (unsigned int *)user;

    if(*max_size && *max_size <= asn1->len.size)
        return 1;

    return 0;
}

/*
**  NAME
**    DetectOversizeLength::
*/
/**
**  This is just a wrapper to the traverse function.  It's important because
**  this allows us to do more with individual nodes in the future.
**
**  @return integer
**
**  @retval 0 failed
**  @rteval 1 detected
*/
static int DetectOversizeLength(ASN1_TYPE *asn1, unsigned int max_size)
{
    return asn1_traverse(asn1, (void *)&max_size, OversizeLength);
}

/*
**  NAME
**    Asn1DetectFuncs::
*/
/**
**  The main function for adding ASN.1 detection type functionality.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int Asn1DetectFuncs(ASN1_TYPE *asn1, ASN1_CTXT *ctxt, int dec_ret_val)
{
    int iRet = 0;

    /*
    **  Print first, before we do other detection.  If print is the only
    **  option, then we want to evaluate this option as true and continue.
    **  Otherwise, if another option is wrong, then we 
    */
    if(ctxt->print)
    {
        asn1_traverse(asn1, NULL, asn1_print_types);
        iRet = 1;
    }

    /*
    **  Let's check the bitstring overflow.
    */
    if(ctxt->bs_overflow)
    {
        iRet = DetectBitStringOverflow(asn1);
        if(iRet)
            return 1;
    }

    if(ctxt->double_overflow)
    {
        iRet = DetectDoubleOverflow(asn1);
        if(iRet)
            return 1;
    }

    if(ctxt->length)
    {
        iRet = DetectOversizeLength(asn1, ctxt->max_length);

        /*
        **  If we didn't detect any oversize length in the decoded structs,
        **  that might be because we had a really overlong length that is
        **  bigger than our data type could hold.  In this case, it's 
        **  overlong too.
        */
        if(!iRet && dec_ret_val == ASN1_ERR_OVERLONG_LEN)
            iRet = 1;

        /*
        **  We add this return in here, so that we follow suit with the
        **  previous detections.  Just trying to short-circuit any future
        **  problems if we change the code flow here.
        */
        if(iRet)
            return 1;
    }

    return iRet;
}

/*
**  NAME
**    Asn1Detect::
*/
/**
**  The main snort detection function.  We grab the context ptr from the
**  otn and go forth.  We check all the offsets to make sure we're in
**  bounds, etc.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int Asn1Detect(Packet *p, OptTreeNode *otn, OptFpList *fp_list)
{
    ASN1_CTXT *ctxt;
    ASN1_TYPE *asn1;
    int iRet;
    unsigned int size;
    char *start;
    char *end;
    char *offset = NULL;

    /*
    **  Failed if there is no data to decode.
    */
    if(!p->data)
        return 0;

    ctxt = (ASN1_CTXT *)fp_list->context;

    start = p->data;
    end   = start + p->dsize;

    switch(ctxt->offset_type)
    {
        case REL_OFFSET:
            if(!doe_ptr)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_ASN1, "[*] No doe_ptr for "
                           "relative offset, so we are bailing.\n"););
                return 0;
            }
                           
            /*
            **  Check that it is in bounds first.
            */
            if(!inBounds(start, end, doe_ptr))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_ASN1, "[*] ASN.1 bounds "
                           "check failed for doe_ptr.\n"););
                return 0;
            }

            if(!inBounds(start, end, doe_ptr+ctxt->offset))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_ASN1, "[*] ASN.1 bounds "
                           "check failed doe_ptr+offset.\n"););
                return 0;
            }

            offset = doe_ptr+ctxt->offset;
            break;

        case ABS_OFFSET:
        default:
            if(!inBounds(start, end, start+ctxt->offset))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_ASN1, "[*] ASN.1 bounds "
                           "check failed.\n"););
                return 0;
            }

            offset = start+ctxt->offset;
            break;
    }

    /*
    **  Final Check.  We are good to go now.
    */
    if(!inBounds(start,end,offset))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_ASN1, "[*] ASN.1 bounds "
                   "check failed.\n"););
        return 0;
    }

    /*
    **  Set size for asn1_decode().  This should never be -1 since
    **  we do the previous in bounds check.
    */
    size = end - offset;

    iRet = asn1_decode(offset, size, &asn1);
    if(iRet && !asn1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_ASN1, "[*] ASN.1 decode failed "
                   "miserably.\n"););
        return 0;
    }

    /*
    **  Let's do detection now.
    */
    if(Asn1DetectFuncs(asn1, ctxt, iRet))
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);

    return 0;
}

static void Asn1Init(char *data, OptTreeNode *otn, int protocol)
{
    ASN1_CTXT *asn1;
    OptFpList *ofl;

    /* 
     * allocate the data structure and attach 
     * it to the rule's data struct list 
     */
    asn1 = (ASN1_CTXT *)SnortAlloc(sizeof(ASN1_CTXT));
    memset(asn1, 0x00, sizeof(ASN1_CTXT));

    Asn1RuleParse(data, otn, asn1);

    ofl = AddOptFuncToList(Asn1Detect, otn);

    ofl->context = (void *)asn1;
}

void SetupAsn1()
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("asn1", Asn1Init);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: ASN1 Setup\n"););
}

