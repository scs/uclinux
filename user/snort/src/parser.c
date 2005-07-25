/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <ctype.h>
#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#include <pwd.h>
#endif /* !WIN32 */
#include <unistd.h>

#include "src/preprocessors/flow/flow_print.h"
#include "rules.h"
#include "parser.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "detect.h"
#include "fpcreate.h"
#include "log.h"
#include "generators.h"
#include "tag.h"
#include "signature.h"
#include "sfthreshold.h"
#include "sfutil/sfthd.h"
#include "snort.h"
#include "inline.h"
#include "event_queue.h"
#include "asn1.h"

ListHead Alert;         /* Alert Block Header */
ListHead Log;           /* Log Block Header */
ListHead Pass;          /* Pass Block Header */
ListHead Activation;    /* Activation Block Header */
ListHead Dynamic;       /* Dynamic Block Header */
ListHead Drop;
ListHead SDrop;
ListHead Reject;

RuleTreeNode *rtn_tmp;      /* temp data holder */
OptTreeNode *otn_tmp;       /* OptTreeNode temp ptr */
ListHead *head_tmp = NULL;  /* ListHead temp ptr */

RuleListNode *RuleLists;

struct VarEntry *VarHead = NULL;

char *file_name;        /* current rules file being processed */
int file_line;          /* current line being processed in the rules
                         * file */
int rule_count;         /* number of rules generated */
int head_count;         /* number of header blocks (chain heads?) */
int opt_count;          /* number of chains */

int dynamic_rules_present;
int active_dynamic_nodes;

extern unsigned int giFlowbitSize; /** size of flowbits tracking */

extern SNORT_EVENT_QUEUE g_event_queue;

extern KeywordXlateList *KeywordList;   /* detection/response plugin keywords */
extern PreprocessKeywordList *PreprocessKeywords;   /* preprocessor plugin
                             * keywords */
extern OutputFuncNode *AlertList;   /* Alert function list */
extern OutputFuncNode *LogList; /* log function list */

#ifdef GIDS
extern OutputFuncNode *DropList;
extern OutputFuncNode *SDropList;
extern OutputFuncNode *RejectList;
#endif /* GIDS */

/* Local Function Declarations */
void ProcessHeadNode(RuleTreeNode *, ListHead *, int);
void ParseSID(char *, OptTreeNode *);
void ParseRev(char *, OptTreeNode *);
void XferHeader(RuleTreeNode *, RuleTreeNode *);
void DumpChain(RuleTreeNode *, char *, char *);
void IntegrityCheck(RuleTreeNode *, char *, char *);
void SetLinks(RuleTreeNode *, RuleTreeNode *);
int ProcessIP(char *, RuleTreeNode *, int );
IpAddrSet *AllocAddrNode(RuleTreeNode *, int );
int TestHeader(RuleTreeNode *, RuleTreeNode *);
RuleTreeNode *GetDynamicRTN(int, RuleTreeNode *);
OptTreeNode *GetDynamicOTN(int, RuleTreeNode *);
void AddrToFunc(RuleTreeNode *, int);
void PortToFunc(RuleTreeNode *, int, int, int);
void SetupRTNFuncList(RuleTreeNode *);


/****************************************************************************
 *
 * Function: ParseRulesFile(char *, int)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *            inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRulesFile(char *file, int inclevel)
{
    FILE *thefp;        /* file pointer for the rules file */
    char buf[STD_BUF];      /* file read buffer */
    char *index;        /* buffer indexing pointer */
    char *stored_file_name = file_name;
    int stored_file_line = file_line;
    char *saved_line = NULL;
    int continuation = 0;
    char *new_line = NULL;
    struct stat file_stat; /* for include path testing */

    if(inclevel == 0)
    {
        if(!pv.quiet_flag)
        {
            LogMessage("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            LogMessage("Initializing rule chains...\n");
        }
    }

    stored_file_line = file_line;
    stored_file_name = file_name;
    file_line = 0;
    
    /* Changed to
     *  stat the file relative to the  current directory
     *  if that fails - stat it relative to the directory
     *  that the configuration file was in
     */ 

    file_name = strdup(file);
    if(file_name == NULL)
    {
        FatalError("ParseRulesFile strdup failed: %s\n", 
                   strerror(errno));
    }

    /* Well the file isn't the one that we thought it was - lets
       try the file relative to the current directory
     */
    
    if(stat(file_name, &file_stat) < 0) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ParseRulesFile: stat "
                                "on %s failed - going to config_dir\n", file_name););
        
        free(file_name);

        file_name = calloc(strlen(file) + strlen(pv.config_dir) + 1, 
                sizeof(char));

        if(file_name == NULL)
        {
            FatalError("ParseRulesFile calloc failed: %s\n", 
                       strerror(errno));
        }

        strlcpy(file_name, pv.config_dir, strlen(file) + 
                strlen(pv.config_dir) + 1);

        strlcat(file_name, file, strlen(file) + strlen(pv.config_dir) + 1);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ParseRulesFile: Opening "
                    "and parsing %s\n", file_name););
    }

    /* open the rules file */
    if((thefp = fopen(file_name, "r")) == NULL)
    {
        FatalError("Unable to open rules file: %s or %s\n", file, 
                   file_name);
    }

    /* clear the line buffer */
    bzero((char *) buf, STD_BUF);


    /* loop thru each file line and send it to the rule parser */
    while((fgets(buf, STD_BUF, thefp)) != NULL)
    {
        /*
         * inc the line counter so the error messages know which line to
         * bitch about
         */
        file_line++;

        index = buf;

#ifdef DEBUG2
	LogMessage("Got line %s (%d): %s\n", file_name, file_line, buf);
#endif
        /* advance through any whitespace at the beginning of the line */
        while(*index == ' ' || *index == '\t')
            index++;

        /* if it's not a comment or a <CR>, send it to the parser */
        if((*index != '#') && (*index != 0x0a) && (*index != ';') && 
                (index != NULL))
        {
            if(continuation == 1)
            {
                new_line = (char *) calloc((strlen(saved_line) + strlen(index)
                            +1), sizeof(char)); 
                strncat(new_line, saved_line, strlen(saved_line));
                strncat(new_line, index, strlen(index));
                free(saved_line);
                saved_line = NULL;
                index = new_line;

                if(strlen(index) > PARSERULE_SIZE)
                {
                    FatalError("Please don't try to overflow the parser, "
                            "that's not very nice of you... (%d-byte "
                            "limit on rule size)\n", PARSERULE_SIZE);
                }

                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"concat rule: %s\n", 
                            new_line););
            }

            /* check for a '\' continuation character at the end of the line
             * if it's there we need to get the next line in the file
             */
            if(ContinuationCheck(index) == 0) 
            {
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                            "[*] Processing rule: %s\n", index););

                ParseRule(thefp, index, inclevel);

                if(new_line != NULL)
                {
                    free(new_line);
                    new_line = NULL;
                    continuation = 0;
                }
            }
            else
            {
                /* save the current line */
                saved_line = strdup(index);

                /* set the flag to let us know the next line is 
                 * a continuation line
                 */ 
                continuation = 1;
            }   
        }

        bzero((char *) buf, STD_BUF);
    }

    if(file_name)
        free(file_name);

    file_name = stored_file_name;
    file_line = stored_file_line;

    if(inclevel == 0 && !pv.quiet_flag)
    {
	LogMessage("%d Snort rules read...\n", rule_count);
	LogMessage("%d Option Chains linked into %d Chain Headers\n", opt_count, 
                head_count);
	LogMessage("%d Dynamic rules\n", dynamic_rules_present);
	LogMessage("+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
    }

    fclose(thefp);

    /* plug all the dynamic rules together */
    if(dynamic_rules_present)
    {
        LinkDynamicRules();
    }

    if(inclevel == 0)
    {
#ifdef DEBUG
        DumpRuleChains();
#endif

        IntegrityCheckRules();
        /*FindMaxSegSize();*/
    }

    return;
}



int ContinuationCheck(char *rule)
{
    char *idx;  /* indexing var for moving around on the string */

    idx = rule + strlen(rule) - 1;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"initial idx set to \'%c\'\n", 
                *idx););

    while(isspace((int)*idx))
    {
        idx--;
    }

    if(*idx == '\\')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got continuation char, "
                    "clearing char and returning 1\n"););

        /* clear the '\' so there isn't a problem on the appended string */
        *idx = '\x0';
        return 1;
    }

    return 0;
}


int CheckRule(char *str)
{
    int len;
    int got_paren = 0;
    int got_semi = 0;
    char *index;

    len = strlen(str);

    index = str + len - 1; /* go to the end of the string */

    while((isspace((int)*index)))
    {
        if(index > str)
            index--;
        else
            return 0;
    }

    /* the last non-whitspace character should be a ')' */
    if(*index == ')')
    {
        got_paren = 1;
        index--;
    }

    while((isspace((int)*index)))
    {
        if(index > str)
            index--;
        else
            return 0;
    }

    /* the next to last char should be a semicolon */
    if(*index == ';')
    {
        got_semi = 1;
    }

    if(got_semi && got_paren)
    {
        return 1;
    }
    else
    {
        /* check for a '(' to make sure that rule options are being used... */
        for(index = str; index < str+len; index++)
        {
            if(*index == '(')
            {
                return 0;
            }
        }

        return 1;
    }

}

void DumpRuleChains()
{
    RuleListNode *rule;

    rule = RuleLists;

    while(rule != NULL)
    {
        DumpChain(rule->RuleList->IpList, rule->name, "IP Chains");
        DumpChain(rule->RuleList->TcpList, rule->name, "TCP Chains");
        DumpChain(rule->RuleList->UdpList, rule->name, "UDP Chains");
        DumpChain(rule->RuleList->IcmpList, rule->name, "ICMP Chains");
        rule = rule->next;
    }
}

void IntegrityCheckRules()
{
    RuleListNode *rule;

    rule = RuleLists;

    if(!pv.quiet_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Performing Rule "
                    "List Integrity Tests...\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"----------------"
                    "-----------------------\n"););
    }

    while(rule != NULL)
    {
        IntegrityCheck(rule->RuleList->IpList, rule->name, "IP Chains");
        IntegrityCheck(rule->RuleList->TcpList, rule->name, "TCP Chains");
        IntegrityCheck(rule->RuleList->UdpList, rule->name, "UDP Chains");
        IntegrityCheck(rule->RuleList->IcmpList, rule->name, "ICMP Chains");
        rule = rule->next;
    }

    if(!pv.quiet_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "---------------------------------------\n\n"););
    }
}

/****************************************************************************
 *
 * Function: ParseRule(FILE*, char *, int)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *            inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRule(FILE *rule_file, char *prule, int inclevel)
{
    char **toks;        /* dbl ptr for mSplit call, holds rule tokens */
    int num_toks;       /* holds number of tokens found by mSplit */
    int rule_type;      /* rule type enumeration variable */
    char rule[PARSERULE_SIZE];
    int protocol = 0;
    char *tmp;
    RuleTreeNode proto_node;
    RuleListNode *node = RuleLists;

    /* chop off the <CR/LF> from the string */
    strip(prule);

    /* expand all variables */
    bzero((void *)rule, sizeof(rule));

    strncpy(rule, ExpandVars(prule), PARSERULE_SIZE-1);

    /* break out the tokens from the rule string */
    toks = mSplit(rule, " ", 10, &num_toks, 0);


    /* clean house */
    bzero((char *) &proto_node, sizeof(RuleTreeNode));

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"[*] Rule start\n"););

    /* figure out what we're looking at */
    rule_type = RuleType(toks[0]);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule type: "););

    /* handle non-rule entries */
    switch(rule_type)
    {
#ifdef GIDS
        case RULE_DROP:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Drop\n"););

            /* if we are not listening to iptables, let's ignore
             * any drop rules in the configuration file */
            if (!InlineMode())
            {
                return;
            }
            break;
				
        case RULE_SDROP:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"SDrop\n"););
			  
            /* if we are not listening to iptables, let's ignore
             * any sdrop rules in the configuration file */
            if (!InlineMode())
            {
                return;
            }
            break;
				
        case RULE_REJECT:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Reject\n"););
			  
            /* if we are not listening to iptables, let's ignore
             * any reject rules in the configuration file */
            if (!InlineMode())
            {
                return;
            }
            break;
#endif /* GIDS */
				
        case RULE_PASS:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Pass\n"););
            break;

        case RULE_LOG:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Log\n"););
            break;

        case RULE_ALERT:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Alert\n"););
            break;

        case RULE_INCLUDE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Include\n"););
            if(*toks[1] == '$')
            {
                if((tmp = VarGet(toks[1]+1)) == NULL)
                {
                    FatalError("%s(%d) => Undefined variable %s\n", 
                               file_name, file_line, toks[1]);
                }
            }
            else
            {
                tmp = toks[1];
            }

            ParseRulesFile(tmp, inclevel + 1);
            mSplitFree(&toks, num_toks);
            return;

        case RULE_VAR:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Variable\n"););
            VarDefine(toks[1], toks[2]);
            mSplitFree(&toks, num_toks);
            return;

        case RULE_PREPROCESS:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Preprocessor\n"););
            ParsePreprocessor(rule);
            mSplitFree(&toks, num_toks);
            return;

        case RULE_OUTPUT:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Output Plugin\n"););
            ParseOutputPlugin(rule);
            mSplitFree(&toks, num_toks);
            return;

        case RULE_ACTIVATE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Activation rule\n"););
            break;

        case RULE_DYNAMIC:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Dynamic rule\n"););
            break;

        case RULE_CONFIG:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule file config\n"););
            ParseConfig(rule);
            mSplitFree(&toks, num_toks);
            return;

        case RULE_DECLARE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule type declaration\n"););
            ParseRuleTypeDeclaration(rule_file, rule);
            mSplitFree(&toks, num_toks);
            return;
 
        case RULE_THRESHOLD:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Threshold\n"););
            ParseSFThreshold(rule_file, rule);
            mSplitFree(&toks, num_toks);
            return;
        
	case RULE_SUPPRESS:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Suppress\n"););
            ParseSFSuppress(rule_file, rule);
            mSplitFree(&toks, num_toks);
            return;
 
        case RULE_UNKNOWN:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Unknown rule type, might be declared\n"););

            /* find out if this ruletype has been declared */
            while(node != NULL)
            {
                if(!strcasecmp(node->name, toks[0]))
                    break;
                node = node->next;
            }

            if(node == NULL)
            {
                 FatalError("%s(%d) => Unknown rule type: %s\n",
                            file_name, file_line, toks[0]);
            }

            break; 

        default:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Invalid input: %s\n", prule););
            mSplitFree(&toks, num_toks);
            return;
    }

    if(num_toks < 7)
    {
        FatalError("%s(%d): Bad rule in rules file\n", file_name, file_line);
    }

    if(!CheckRule(prule))
    {
        FatalError("Unterminated rule in file %s, line %d\n" 
                   "   (Snort rules must be contained on a single line or\n"
                   "    on multiple lines with a '\\' continuation character\n"
                   "    at the end of the line,  make sure there are no\n"
                   "    carriage returns before the end of this line)\n",
                   file_name, file_line);
        return;
    }

    if (rule_type == RULE_UNKNOWN)
        proto_node.type = node->mode;
    else
        proto_node.type = rule_type;

    /* set the rule protocol */
    protocol = WhichProto(toks[1]);

    /* Process the IP address and CIDR netmask */
    /* changed version 1.2.1 */
    /*
     * "any" IP's are now set to addr 0, netmask 0, and the normal rules are
     * applied instead of checking the flag
     */
    /*
     * if we see a "!<ip number>" we need to set a flag so that we can
     * properly deal with it when we are processing packets
     */
    /* we found a negated address */
    /* if( *toks[2] == '!' )    
       {
       proto_node.flags |= EXCEPT_SRC_IP;
       ProcessIP(&toks[2][1], &proto_node, SRC);
       }
       else
       {*/
    ProcessIP(toks[2], &proto_node, SRC);
    /*}*/

    /* check to make sure that the user entered port numbers */
    /* sometimes they forget/don't know that ICMP rules need them */
    if(!strcasecmp(toks[3], "->") ||
            !strcasecmp(toks[3], "<>"))
    {
        FatalError("%s:%d => Port value missing in rule!\n", 
                   file_name, file_line);
    }

    /* do the same for the port */
    if(ParsePort(toks[3], (u_short *) & proto_node.hsp,
                (u_short *) & proto_node.lsp, toks[1],
                (int *) &proto_node.not_sp_flag))
    {
        proto_node.flags |= ANY_SRC_PORT;
    }

    if(proto_node.not_sp_flag)
        proto_node.flags |= EXCEPT_SRC_PORT;

    /* New in version 1.3: support for bidirectional rules */
    /*
     * this checks the rule "direction" token and sets the bidirectional flag
     * if the token = '<>'
     */
    if(!strncmp("<>", toks[4], 2))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Bidirectional rule!\n"););
        proto_node.flags |= BIDIRECTIONAL;
    }

    /* changed version 1.8.4
     * Die when someone has tried to define a rule character other than
       -> or <>
    */
    if(strcmp("->", toks[4]) && strcmp("<>", toks[4]))
    {
        FatalError("%s(%d): Illegal direction specifier: %s\n", file_name, 
                file_line, toks[4]);
    }


    /* changed version 1.2.1 */
    /*
     * "any" IP's are now set to addr 0, netmask 0, and the normal rules are
     * applied instead of checking the flag
     */
    /*
     * if we see a "!<ip number>" we need to set a flag so that we can
     * properly deal with it when we are processing packets
     */
    /* we found a negated address */
    ProcessIP(toks[5], &proto_node, DST);

    if(ParsePort(toks[6], (u_short *) & proto_node.hdp,
                (u_short *) & proto_node.ldp, toks[1],
                (int *) &proto_node.not_dp_flag))
    {
        proto_node.flags |= ANY_DST_PORT;
    }

    /* if there is anything beyond the dst port, it must begin with "(" */
    if (num_toks > 7 && toks[7][0] != '(')
    {
        FatalError("%s(%d): The rule option section (starting with a '(') must "
                   "follow immediately after the destination port.  "
                   "This means port lists are not supported.\n",
                   file_name, file_line);
    }

    if(proto_node.not_dp_flag)
        proto_node.flags |= EXCEPT_DST_PORT;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"proto_node.flags = 0x%X\n", proto_node.flags););
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Processing Head Node....\n"););

    switch(rule_type)
    {
#ifdef GIDS
        case RULE_DROP:
            if (InlineMode())
            {
                ProcessHeadNode(&proto_node, &Drop, protocol);
            }
            break;
			 
        case RULE_SDROP:
            if (InlineMode())
            {
                ProcessHeadNode(&proto_node, &SDrop, protocol);
            }
            break;
			 
        case RULE_REJECT:
            if (InlineMode())
            {
                ProcessHeadNode(&proto_node, &Reject, protocol);
            }
            break;
#endif /* GIDS */		 
		 
        case RULE_ALERT:
            ProcessHeadNode(&proto_node, &Alert, protocol);
            break;

        case RULE_LOG:
            ProcessHeadNode(&proto_node, &Log, protocol);
            break;

        case RULE_PASS:
            ProcessHeadNode(&proto_node, &Pass, protocol);
            break;

        case RULE_ACTIVATE:
            ProcessHeadNode(&proto_node, &Activation, protocol);
            break;

        case RULE_DYNAMIC:
            ProcessHeadNode(&proto_node, &Dynamic, protocol);
            break;

        case RULE_UNKNOWN:
            ProcessHeadNode(&proto_node, node->RuleList, protocol);
            break;

        default:
            FatalError("Unable to determine rule type (%s) for processing, exiting!\n", toks[0]);
    }

    rule_count++;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Parsing Rule Options...\n"););

    if (rule_type == RULE_UNKNOWN)
        ParseRuleOptions(rule, node->mode, protocol);
    else
        ParseRuleOptions(rule, rule_type, protocol);

    mSplitFree(&toks, num_toks);

    return;
}

/****************************************************************************
 *
 * Function: ProcessHeadNode(RuleTreeNode *, ListHead *, int)
 *
 * Purpose:  Process the header block info and add to the block list if
 *           necessary
 *
 * Arguments: test_node => data generated by the rules parsers
 *            list => List Block Header refernece
 *            protocol => ip protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
void ProcessHeadNode(RuleTreeNode * test_node, ListHead * list, int protocol)
{
    int match = 0;
    RuleTreeNode *rtn_idx;
    RuleTreeNode *rtn_prev;
    RuleTreeNode *rtn_head_ptr;
    int count = 0;
    int insert_complete = 0;
#ifdef DEBUG
    int i;
#endif

    /* select the proper protocol list to attach the current rule to */
    switch(protocol)
    {
        case IPPROTO_TCP:
            rtn_idx = list->TcpList;
            break;

        case IPPROTO_UDP:
            rtn_idx = list->UdpList;
            break;

        case IPPROTO_ICMP:
            rtn_idx = list->IcmpList;
            break;

        case ETHERNET_TYPE_IP:
            rtn_idx = list->IpList;
            break;

        default:
            rtn_idx = NULL;
            break;
    }

    /* 
     * save which list we're on in case we need to do an insertion
     * sort on a new node
     */
    rtn_head_ptr = rtn_idx;

    /*
     * if the list head is NULL (empty), make a new one and attach the
     * ListHead to it
     */
    if(rtn_idx == NULL)
    {
        head_count++;

        switch(protocol)
        {
            case IPPROTO_TCP:
                list->TcpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
                        sizeof(char));
                rtn_tmp = list->TcpList;
                break;

            case IPPROTO_UDP:
                list->UdpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
                        sizeof(char));
                rtn_tmp = list->UdpList;
                break;

            case IPPROTO_ICMP:
                list->IcmpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
                        sizeof(char));
                rtn_tmp = list->IcmpList;
                break;

            case ETHERNET_TYPE_IP:
                list->IpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
                        sizeof(char));
                rtn_tmp = list->IpList;
                break;

        }

        /* copy the prototype header data into the new node */
        XferHeader(test_node, rtn_tmp);

        rtn_tmp->head_node_number = head_count;

        /* null out the down (options) pointer */
        rtn_tmp->down = NULL;

        /* add the function list to the new rule */
        SetupRTNFuncList(rtn_tmp);

        /* add link to parent listhead */
        rtn_tmp->listhead = list;

        return;
    }

    /* see if this prototype node matches any of the existing header nodes */
    match = TestHeader(rtn_idx, test_node);

    while((rtn_idx->right != NULL) && !match)
    {
        count++;
        match = TestHeader(rtn_idx, test_node);

        if(!match)
            rtn_idx = rtn_idx->right;
        else
            break;
    }

    /*
     * have to check this twice since my loop above exits early, which sucks
     * but it's not performance critical
     */
    match = TestHeader(rtn_idx, test_node);

    /*
     * if it doesn't match any of the existing nodes, make a new node and
     * stick it at the end of the list
     */
    if(!match)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Building New Chain head node\n"););

        head_count++;

        /* build a new node */
        //rtn_idx->right = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
        rtn_tmp = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
                sizeof(char));

        /* set the global ptr so we can play with this from anywhere */
        //rtn_tmp = rtn_idx->right;

        /* uh oh */
        if(rtn_tmp == NULL)
        {
            FatalError("Unable to allocate Rule Head Node!!\n");
        }

        /* copy the prototype header info into the new header block */
        XferHeader(test_node, rtn_tmp);

        rtn_tmp->head_node_number = head_count;
        rtn_tmp->down = NULL;

        /* initialize the function list for the new RTN */
        SetupRTNFuncList(rtn_tmp);

        /* add link to parent listhead */
        rtn_tmp->listhead = list;
        
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                "New Chain head flags = 0x%X\n", rtn_tmp->flags););

        /* we do an insertion sort of new RTNs for TCP/UDP traffic */
        if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        {
            /* 
             * insert the new node into the RTN chain, order by destination
             * port
             */
            rtn_idx = rtn_head_ptr;
            rtn_prev = NULL;
            insert_complete = 0;

            /* 
             * Loop thru the RTN list and check to see of the low dest port
             * of the new node is greater than the low dest port of the 
             * new node.  If it is, insert the new node ahead of (to the 
             * left) of the existing node.
             */
            if(rtn_tmp->flags & EXCEPT_DST_PORT)
            {
                switch(protocol)
                {
                    case IPPROTO_TCP:
                        rtn_tmp->right = list->TcpList;
                        list->TcpList = rtn_tmp;
                        break;

                    case IPPROTO_UDP:
                        rtn_tmp->right = list->UdpList;
                        list->UdpList = rtn_tmp;
                        break;
                }

                rtn_head_ptr = rtn_tmp;
                insert_complete = 1;
            }
            else
            {
                while(rtn_idx != NULL)
                {
                    if(rtn_idx->flags & EXCEPT_DST_PORT || 
                       rtn_idx->ldp < rtn_tmp->ldp)
                    {
                        rtn_prev = rtn_idx;
                        rtn_idx = rtn_idx->right;
                    }
                    else if(rtn_idx->ldp == rtn_tmp->ldp)
                    {
                        rtn_tmp->right = rtn_idx->right;
                        rtn_idx->right = rtn_tmp;
                        insert_complete = 1;
                        break;
                    }
                    else
                    {
                        rtn_tmp->right = rtn_idx;

                        if(rtn_prev != NULL)
                        {
                            rtn_prev->right = rtn_tmp;
                        }
                        else 
                        {
                            switch(protocol)
                            {
                                case IPPROTO_TCP:
                                    list->TcpList = rtn_tmp;
                                    break;

                                case IPPROTO_UDP:
                                    list->UdpList = rtn_tmp;
                                    break;
                            }

                            rtn_head_ptr = rtn_tmp;
                        }

                        insert_complete = 1;

                        break;
                    }
                } 
            }

            if(!insert_complete)
            {
                rtn_prev->right = rtn_tmp;   
            }
            
            rtn_idx = rtn_head_ptr;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, 
                    "New %s node inserted, new order:\n", 
                    protocol == IPPROTO_TCP?"TCP":"UDP"););
            
#ifdef DEBUG
            i = 0;

            while(rtn_idx != NULL)
            {
                if(rtn_idx->flags & EXCEPT_DST_PORT)
                {
                    LogMessage("!");
                }

                DebugMessage(DEBUG_CONFIGRULES, "%d ", rtn_idx->ldp);
                rtn_idx = rtn_idx->right;
                if(i++ == 10)
                {
                    DebugMessage(DEBUG_CONFIGRULES, "\n");
                    i = 0;
                }
            }
            DebugMessage(DEBUG_CONFIGRULES, "\n");
#endif
        }
        else
        {
            rtn_idx->right = rtn_tmp;
        }
    }
    else
    {
        rtn_tmp = rtn_idx;
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                "Chain head %d  flags = 0x%X\n", count, rtn_tmp->flags););

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "Adding options to chain head %d\n", count););
    }
}


/****************************************************************************
 *
 * Function: AddRuleFuncToList(int (*func)(), RuleTreeNode *)
 *
 * Purpose:  Adds RuleTreeNode associated detection functions to the
 *          current rule's function list
 *
 * Arguments: *func => function pointer to the detection function
 *            rtn   => pointer to the current rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void AddRuleFuncToList(int (*func) (Packet *, struct _RuleTreeNode *, struct _RuleFpList *), RuleTreeNode * rtn)
{
    RuleFpList *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Adding new rule to list\n"););

    idx = rtn->rule_func;

    if(idx == NULL)
    {
        rtn->rule_func = (RuleFpList *) calloc(sizeof(RuleFpList), sizeof(char));

        rtn->rule_func->RuleHeadFunc = func;
    }
    else
    {
        while(idx->next != NULL)
            idx = idx->next;

        idx->next = (RuleFpList *) calloc(sizeof(RuleFpList), sizeof(char));

        idx = idx->next;
        idx->RuleHeadFunc = func;
    }
}


/****************************************************************************
 *
 * Function: SetupRTNFuncList(RuleTreeNode *)
 *
 * Purpose: Configures the function list for the rule header detection
 *          functions (addrs and ports)
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *
 * Returns: void function
 *
 ***************************************************************************/
void SetupRTNFuncList(RuleTreeNode * rtn)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Initializing RTN function list!\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Functions: "););

    if(rtn->flags & BIDIRECTIONAL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckBidirectional->\n"););
        AddRuleFuncToList(CheckBidirectional, rtn);
    }
    else
    {
        /* Attach the proper port checking function to the function list */
        /*
         * the in-line "if's" check to see if the "any" or "not" flags have
         * been set so the PortToFunc call can determine which port testing
         * function to attach to the list
         */
        PortToFunc(rtn, (rtn->flags & ANY_DST_PORT ? 1 : 0),
                   (rtn->flags & EXCEPT_DST_PORT ? 1 : 0), DST);

        /* as above */
        PortToFunc(rtn, (rtn->flags & ANY_SRC_PORT ? 1 : 0),
                   (rtn->flags & EXCEPT_SRC_PORT ? 1 : 0), SRC);

	    /* link in the proper IP address detection function */
        AddrToFunc(rtn, SRC);

        /* last verse, same as the first (but for dest IP) ;) */
        AddrToFunc(rtn, DST);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"RuleListEnd\n"););

    /* tack the end (success) function to the list */
    AddRuleFuncToList(RuleListEnd, rtn);
}



/****************************************************************************
 *
 * Function: AddrToFunc(RuleTreeNode *, u_long, u_long, int, int)
 *
 * Purpose: Links the proper IP address testing function to the current RTN
 *          based on the address, netmask, and addr flags
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            ip =>  IP address of the current rule
 *            mask => netmask of the current rule
 *            exception_flag => indicates that a "!" has been set for this
 *                              address
 *            mode => indicates whether this is a rule for the source
 *                    or destination IP for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void AddrToFunc(RuleTreeNode * rtn, int mode)
{
    /*
     * if IP and mask are both 0, this is a "any" IP and we don't need to
     * check it
     */
    switch(mode)
    {
        case SRC:
            if((rtn->flags & ANY_SRC_IP) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckSrcIP -> "););
                AddRuleFuncToList(CheckSrcIP, rtn);
            }

            break;

        case DST:
            if((rtn->flags & ANY_DST_IP) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckDstIP -> "););
                AddRuleFuncToList(CheckDstIP, rtn);
            }

            break;
    }
}



/****************************************************************************
 *
 * Function: PortToFunc(RuleTreeNode *, int, int, int)
 *
 * Purpose: Links in the port analysis function for the current rule
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            any_flag =>  accept any port if set
 *            except_flag => indicates negation (logical NOT) of the test
 *            mode => indicates whether this is a rule for the source
 *                    or destination port for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void PortToFunc(RuleTreeNode * rtn, int any_flag, int except_flag, int mode)
{
    /*
     * if the any flag is set we don't need to perform any test to match on
     * this port
     */
    if(any_flag)
        return;

    /* if the except_flag is up, test with the "NotEq" funcs */
    if(except_flag)
    {
        switch(mode)
        {
            case SRC:
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckSrcPortNotEq -> "););
                AddRuleFuncToList(CheckSrcPortNotEq, rtn);
                break;

            case DST:
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckDstPortNotEq -> "););
                AddRuleFuncToList(CheckDstPortNotEq, rtn);
                break;
        }

        return;
    }
    /* default to setting the straight test function */
    switch(mode)
    {
        case SRC:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckSrcPortEqual -> "););
            AddRuleFuncToList(CheckSrcPortEqual, rtn);
            break;

        case DST:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckDstPortEqual -> "););
            AddRuleFuncToList(CheckDstPortEqual, rtn);
            break;
    }

    return;
}





/****************************************************************************
 *
 * Function: ParsePreprocessor(char *)
 *
 * Purpose: Walks the preprocessor function list looking for the user provided
 *          keyword.  Once found, call the preprocessor's initialization
 *          function.
 *
 * Arguments: rule => the preprocessor initialization string from the rules file
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParsePreprocessor(char *rule)
{
    char **toks;        /* pointer to the tokenized array parsed from
                         * the rules list */
    char **pp_head;     /* parsed keyword list, with preprocessor
                         * keyword being the 2nd element */
    char *funcname;     /* the ptr to the actual preprocessor keyword */
    char *pp_args = NULL;   /* parsed list of arguments to the
                             * preprocessor */
    int num_arg_toks;   /* number of argument tokens returned by the mSplit function */
    int num_head_toks;  /* number of head tokens returned by the mSplit function */
    int found = 0;      /* flag var */
    PreprocessKeywordList *pl_idx;  /* index into the preprocessor
                                     * keyword/func list */

    /* break out the arguments from the keywords */
    toks = mSplit(rule, ":", 2, &num_arg_toks, '\\');

    if(num_arg_toks > 1)
    {
        /*
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"toks[1] = %s\n", toks[1]););
        */
        /* the args are everything after the ":" */
        pp_args = toks[1];
    }

    /* split the head section for the preprocessor keyword */
    pp_head = mSplit(toks[0], " ", 2, &num_head_toks, '\\');

    /* set a pointer to the actual keyword */
    funcname = pp_head[1];

    /* set the index to the head of the keyword list */
    pl_idx = PreprocessKeywords;

    /* walk the keyword list */
    while(pl_idx != NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
				"comparing: \"%s\" => \"%s\"\n",
				funcname, pl_idx->entry.keyword););
        /* compare the keyword against the current list element's keyword */
        if(!strcasecmp(funcname, pl_idx->entry.keyword))
        {
            pl_idx->entry.func(pp_args);
            found = 1;
        }
        if(!found)
        {
            pl_idx = pl_idx->next;
        }
        else
            break;
    }

    if(!found)
    {
        FatalError(" unknown preprocessor \"%s\"\n",
                   funcname);
    }

    mSplitFree(&toks, num_arg_toks);
    mSplitFree(&pp_head, num_head_toks);
}


void ParseOutputPlugin(char *rule)
{
    char **toks;
    char **pp_head;
    char *plugin_name = NULL;
    char *pp_args = NULL;
    int num_arg_toks;
    int num_head_toks;
    OutputKeywordNode *plugin;

    toks = mSplit(rule, ":", 2, &num_arg_toks, '\\');

    if(num_arg_toks > 1)
    {
        pp_args = toks[1];
    }
    pp_head = mSplit(toks[0], " ", 2, &num_head_toks, '\\');

    plugin_name = pp_head[1];

    if(plugin_name == NULL)
    {
        FatalError("%s (%d): Output directive missing output plugin name!\n", 
                file_name, file_line);
    }

    plugin = GetOutputPlugin(plugin_name);
    if( plugin != NULL )
    {
        switch(plugin->node_type)
        {
            case NT_OUTPUT_SPECIAL:
                if(pv.alert_cmd_override)
                    ErrorMessage("command line overrides rules file alert "
                            "plugin!\n");
                if(pv.log_cmd_override)
                    ErrorMessage("command line overrides rules file login "
                            "plugin!\n");
                plugin->func(pp_args);
                break;

            case NT_OUTPUT_ALERT:
                if(!pv.alert_cmd_override)
                {
                    /* call the configuration function for the plugin */
                    plugin->func(pp_args);
                }
                else
                {
                    ErrorMessage("command line overrides rules file alert "
                            "plugin!\n");
                }

                break;

            case NT_OUTPUT_LOG:
                if(!pv.log_cmd_override)
                {
                    /* call the configuration function for the plugin */
                    plugin->func(pp_args);
                }
                else
                {
                    ErrorMessage("command line overrides rules file logging "
                            "plugin!\n");
                }

                break;
        }

    }

    mSplitFree(&toks, num_arg_toks);
    mSplitFree(&pp_head, num_head_toks);
}



/****************************************************************************
 *
 * Function: ParseRuleOptions(char *, int)
 *
 * Purpose:  Process an individual rule's options and add it to the
 *           appropriate rule chain
 *
 * Arguments: rule => rule string
 *            rule_type => enumerated rule type (alert, pass, log)
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRuleOptions(char *rule, int rule_type, int protocol)
{
    char **toks = NULL;
    char **opts = NULL;
    char *idx;
    char *aux;
    int num_toks, original_num_toks=0;
    int i;
    int num_opts;
    int found = 0;
    OptTreeNode *otn_idx;
    KeywordXlateList *kw_idx;
    THDX_STRUCT thdx;
    int one_threshold = 0;
    

    /* set the OTN to the beginning of the list */
    otn_idx = rtn_tmp->down;

    /*
     * make a new one and stick it either at the end of the list or hang it
     * off the RTN pointer
     */
    if(otn_idx != NULL)
    {
        /* loop to the end of the list */
        while(otn_idx->next != NULL)
        {
            otn_idx = otn_idx->next;
        }

        /* setup the new node */
        otn_idx->next = (OptTreeNode *) calloc(sizeof(OptTreeNode), 
                                               sizeof(char));

        /* set the global temp ptr */
        otn_tmp = otn_idx->next;

        if(otn_tmp == NULL)
        {
            FatalError("Unable to alloc OTN: %s", strerror(errno));
        }

        otn_tmp->next = NULL;
        opt_count++;

    }
    else
    {
        /* first entry on the chain, make a new node and attach it */
        otn_idx = (OptTreeNode *) calloc(sizeof(OptTreeNode), sizeof(char));

        bzero((char *) otn_idx, sizeof(OptTreeNode));

        otn_tmp = otn_idx;

        if(otn_tmp == NULL)
        {
            FatalError("Unable to alloc OTN!\n");
        }
        otn_tmp->next = NULL;
        rtn_tmp->down = otn_tmp;
        opt_count++;
    }

    otn_tmp->chain_node_number = opt_count;
    otn_tmp->type = rule_type;
    otn_tmp->proto_node = rtn_tmp;
    otn_tmp->event_data.sig_generator = GENERATOR_SNORT_ENGINE;

    /* add link to parent RuleTreeNode */
    otn_tmp->rtn = rtn_tmp;

    /* find the start of the options block */
    idx = index(rule, '(');
    i = 0;

    if(idx != NULL)
    {
        int one_msg = 0;
        int one_logto = 0;
        int one_activates = 0;
        int one_activated_by = 0;
        int one_count = 0;
        int one_tag = 0;
        int one_sid = 0;
        int one_rev = 0;
        int one_priority = 0;
        int one_classtype = 0;
        int one_stateless = 0;
        
        idx++;

        /* find the end of the options block */
        aux = strrchr(idx, ')');

        /* get rid of the trailing ")" */
        if(aux == NULL)
        {
            FatalError("%s(%d): Missing trailing ')' in rule: %s.\n",
                       file_name, file_line, rule);
        }
        *aux = 0;


        /* seperate all the options out, the seperation token is a semicolon */
        /*
         * NOTE: if you want to include a semicolon in the content of your
         * rule, it must be preceeded with a '\'
         */
        toks = mSplit(idx, ";", 64, &num_toks, '\\');
        original_num_toks = num_toks;  /* so we can properly deallocate toks later */

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   Got %d tokens\n", num_toks););
        /* decrement the number of toks */
        num_toks--;

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Parsing options list: "););

	
        while(num_toks)		
        {
            char* option_name = NULL;
            char* option_args = NULL;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   option: %s\n", toks[i]););

            /* break out the option name from its data */
            opts = mSplit(toks[i], ":", 4, &num_opts, '\\');

            /* can't free opts[0] later if it has been incremented, so
             * must use another variable here */
            option_name = opts[0];
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   option name: %s\n", option_name););
            if (num_opts > 1)
            {
                option_args = opts[1];
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   option args: %s\n", option_args););
            }

            /* advance to the beginning of the data (past the whitespace) */
            while(isspace((int) *option_name))
                option_name++;
	    
            /* figure out which option tag we're looking at */
            if(!strcasecmp(option_name, "msg"))
            {
                ONE_CHECK (one_msg, option_name);
                if(num_opts == 2)
                {
                    ParseMessage(option_args);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else if(!strcasecmp(option_name, "logto"))
            {
                ONE_CHECK (one_logto, option_name);
                if(num_opts == 2)
                {
                    ParseLogto(option_args);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else if(!strcasecmp(option_name, "activates"))
            {
                ONE_CHECK (one_activates, option_name);
                if(num_opts == 2)
                {
                    ParseActivates(option_args);
                    dynamic_rules_present++;
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else if(!strcasecmp(option_name, "activated_by"))
            {
                ONE_CHECK (one_activated_by, option_name);
                if(num_opts == 2)
                {
                    ParseActivatedBy(option_args);
                    dynamic_rules_present++;
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "count"))
            {
                ONE_CHECK (one_count, option_name);
                if(num_opts == 2)
                {
                    if(otn_tmp->type != RULE_DYNAMIC)
                        FatalError("The \"count\" option may only be used with "
                                "the dynamic rule type!\n");
                    ParseCount(opts[1]);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "tag"))
            {
                ONE_CHECK (one_tag, opts[0]);
                if(num_opts == 2)
                {
                    ParseTag(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "threshold"))
            {
                ONE_CHECK (one_threshold, opts[0]);
                if(num_opts == 2)
                {
                    ParseThreshold2(&thdx, opts[1]);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "sid"))
            {
                ONE_CHECK (one_sid, opts[0]);
                if(num_opts == 2)
                {
                    ParseSID(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "rev"))
            {
                ONE_CHECK (one_rev, opts[0]);
                if(num_opts == 2)
                {
                    ParseRev(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "reference"))
            {
                if(num_opts == 2)
                {
                    ParseReference(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "priority"))
            {
                ONE_CHECK (one_priority, opts[0]);
                if(num_opts == 2)
                {
                    ParsePriority(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "classtype"))
            {
                ONE_CHECK (one_classtype, opts[0]);
                if(num_opts == 2)
                {
                    ParseClassType(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else if(!strcasecmp(option_name, "stateless"))
            {
                ONE_CHECK (one_stateless, opts[0]);
                otn_tmp->stateless = 1;
            }
            else
            {
                kw_idx = KeywordList;
                found = 0;

                while(kw_idx != NULL)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "comparing: \"%s\" => \"%s\"\n", 
					    option_name, kw_idx->entry.keyword););

                    if(!strcasecmp(option_name, kw_idx->entry.keyword))
                    {
                        if(num_opts == 2) 
                        {
                            kw_idx->entry.func(option_args, otn_tmp, protocol);
                        } 
                        else 
                        {
                            kw_idx->entry.func(NULL, otn_tmp, protocol);
                        }
                        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "%s->", kw_idx->entry.keyword););
                        found = 1;
                        break;
                    }
                    kw_idx = kw_idx->next;
                }

                if(!found)
                {
                    /* Unrecognized rule option, complain */
                    FatalError("Warning: %s(%d) => Unknown keyword '%s' in "
                               "rule!\n", file_name, file_line, opts[0]);
                }
            }

            mSplitFree(&opts,num_opts);

            --num_toks;
            i++;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"OptListEnd\n"););
        AddOptFuncToList(OptListEnd, otn_tmp);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"OptListEnd\n"););
        AddOptFuncToList(OptListEnd, otn_tmp);
    }

   if( one_threshold )
   {
	   int rstat;
	   thdx.sig_id = otn_tmp->sigInfo.id;
	   thdx.gen_id = GENERATOR_SNORT_ENGINE;
	   if( (rstat=sfthreshold_create( &thdx )) )
	   {
              if( rstat == THD_TOO_MANY_THDOBJ )
	      {
	        FatalError("Rule-Threshold-Parse: could not create a threshold object -- only one per sid, sid = %u\n",thdx.sig_id);
	      }
	      else
	      {
	        FatalError("Unable to add Threshold object for Rule-sid =  %u\n",thdx.sig_id);
	      }
	   }
   }
   
    if(idx != NULL)
       mSplitFree(&toks,original_num_toks);
}


/****************************************************************************
 *
 * Function: RuleType(char *)
 *
 * Purpose:  Determine what type of rule is being processed and return its
 *           equivalent value
 *
 * Arguments: func => string containing the rule type
 *
 * Returns: The rule type designation
 *
 ***************************************************************************/
int RuleType(char *func)
{
    if(func == NULL)
    {
        FatalError("%s(%d) => NULL rule type\n", file_name, file_line);
    }
   
#ifdef GIDS
    if (!strcasecmp(func, "drop"))
        return RULE_DROP;
	 
    if (!strcasecmp(func, "sdrop"))
        return RULE_SDROP;
	 
    if (!strcasecmp(func, "reject"))
        return RULE_REJECT;
#endif /* GIDS */ 
	 
    if(!strcasecmp(func, "log"))
        return RULE_LOG;

    if(!strcasecmp(func, "alert"))
        return RULE_ALERT;

    if(!strcasecmp(func, "pass"))
        return RULE_PASS;

    if(!strcasecmp(func, "var"))
        return RULE_VAR;

    if(!strcasecmp(func, "include"))
        return RULE_INCLUDE;

    if(!strcasecmp(func, "preprocessor"))
        return RULE_PREPROCESS;

    if(!strcasecmp(func, "output"))
        return RULE_OUTPUT;

    if(!strcasecmp(func, "activate"))
        return RULE_ACTIVATE;

    if(!strcasecmp(func, "dynamic"))
        return RULE_DYNAMIC;

    if(!strcasecmp(func, "config"))
        return RULE_CONFIG;

    if(!strcasecmp(func, "ruletype"))
        return RULE_DECLARE;
    
    if(!strcasecmp(func, "threshold"))
        return RULE_THRESHOLD;
    
    if(!strcasecmp(func, "suppress"))
        return RULE_SUPPRESS;

    return RULE_UNKNOWN;
}



/****************************************************************************
 *
 * Function: WhichProto(char *)
 *
 * Purpose: Figure out which protocol the current rule is talking about
 *
 * Arguments: proto_str => the protocol string
 *
 * Returns: The integer value of the protocol
 *
 ***************************************************************************/
int WhichProto(char *proto_str)
{
    if(!strcasecmp(proto_str, "tcp"))
        return IPPROTO_TCP;

    if(!strcasecmp(proto_str, "udp"))
        return IPPROTO_UDP;

    if(!strcasecmp(proto_str, "icmp"))
        return IPPROTO_ICMP;

    if(!strcasecmp(proto_str, "ip"))
        return ETHERNET_TYPE_IP;

    if(!strcasecmp(proto_str, "arp"))
        return ETHERNET_TYPE_ARP;

    /*
     * if we've gotten here, we have a protocol string we din't recognize and
     * should exit
     */
    FatalError("%s(%d) => Bad protocol: %s\n", file_name, file_line, proto_str);

    return 0;
}



int ProcessIP(char *addr, RuleTreeNode *rtn, int mode)
{
    char **toks = NULL;
    int num_toks;
    int i;
    IpAddrSet *tmp_addr;
    char *tmp;
    char *enbracket;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got address string: %s\n", 
                addr););

    if(*addr == '!')
    {
        switch(mode)
        {
            case SRC:
                rtn->flags |= EXCEPT_SRC_IP;
                break;

            case DST:
                rtn->flags |= EXCEPT_DST_IP;
                break;
        }

        addr++;
    }

    if(*addr == '$')
    {
        if((tmp = VarGet(addr + 1)) == NULL)
        {
            FatalError("%s(%d) => Undefined variable %s\n", file_name, 
                    file_line, addr);
        }
    }
    else
    {
        tmp = addr;
    }

    /* check to see if the first char is a 
     * bracket, which signifies a list 
     */
    if(*tmp == '[')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Found IP list!\n"););

        /* *(tmp+strlen(tmp)) = ' ';*/
        enbracket = strrchr(tmp, (int)']'); /* null out the en-bracket */
        if(enbracket) 
            *enbracket = '\x0';
        else
            FatalError("%s(%d) => Unterminated IP List\n", file_name, file_line);

        toks = mSplit(tmp+1, ",", 128, &num_toks, 0);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"mSplit got %d tokens...\n", 
                    num_toks););

        for(i=0; i< num_toks; i++)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"adding %s to IP "
                        "address list\n", toks[i]););
            tmp = toks[i];
            while (isspace((int)*tmp)||*tmp=='[') tmp++;
            enbracket = strrchr(tmp, (int)']'); /* null out the en-bracket */
            if(enbracket) 
                *enbracket = '\x0';

            if (strlen(tmp) == 0)
                continue;
                
            tmp_addr = AllocAddrNode(rtn, mode); 
            ParseIP(tmp, tmp_addr);
            if(tmp_addr->ip_addr == 0 && tmp_addr->netmask == 0)
            {
                switch(mode)
                {
                    case SRC:
                        rtn->flags |= ANY_SRC_IP;
                        break;

                    case DST:
                        rtn->flags |= ANY_DST_IP;
                        break;
                }
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Freeing %d tokens...\n", 
                    num_toks););

        mSplitFree(&toks, num_toks);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "regular IP address, processing...\n"););
        tmp_addr = AllocAddrNode(rtn, mode);
        ParseIP(tmp, tmp_addr);
        if(tmp_addr->ip_addr == 0 && tmp_addr->netmask == 0)
        {
            switch(mode)
            {
                case SRC:
                    rtn->flags |= ANY_SRC_IP;
                    break;

                case DST:
                    rtn->flags |= ANY_DST_IP;
                    break;
            }
        }
    }

    return 0;
}



IpAddrSet *AllocAddrNode(RuleTreeNode *rtn, int mode)
{
    IpAddrSet *idx; /* indexing pointer */

    switch(mode)
    {
        case SRC:
            if(rtn->sip == NULL)
            {
                rtn->sip = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
                if(rtn->sip == NULL)
                {
                    FatalError(" Unable to allocate node for IP list\n");
                }
                return rtn->sip;
            }
            else
            {
                idx = rtn->sip;

                while(idx->next != NULL)
                {
                    idx = idx->next;
                }

                idx->next = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
                if(idx->next == NULL)
                {
                    FatalError(" Unable to allocate node for IP list\n");
                }
                return idx->next;
            }


        case DST:
            if(rtn->dip == NULL)
            {
                rtn->dip = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
                if(rtn->dip == NULL)
                {
                    FatalError(" Unable to allocate node for IP list\n");
                }
                return rtn->dip;
            }
            else
            {
                idx = rtn->dip;

                while(idx->next)
                {
                    idx = idx->next;
                }

                idx->next = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
                if(idx->next == NULL)
                {
                    FatalError(" Unable to allocate node for IP list\n");
                }
                return idx->next;
            }
    }

    return NULL;
}

/****************************************************************************
 *
 * Function: ParsePort(char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: prule_port => port rule string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int ParsePort(char *prule_port, u_short * hi_port, u_short * lo_port, char *proto, int *not_flag)
{
    char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by mSplit() */
    char *rule_port;    /* port string */

    *not_flag = 0;

    /* check for variable */
    if(!strncmp(prule_port, "$", 1))
    {
        if((rule_port = VarGet(prule_port + 1)) == NULL)
        {
            FatalError("%s(%d) => Undefined variable %s\n", file_name, file_line, prule_port);
        }
    }
    else
        rule_port = prule_port;

    if(rule_port[0] == '(')
    {
        /* user forgot to put a port number in for this rule */
        FatalError("%s(%d) => Bad port number: \"%s\"\n", 
                   file_name, file_line, rule_port);
    }


    /* check for wildcards */
    if(!strcasecmp(rule_port, "any"))
    {
        *hi_port = 0;
        *lo_port = 0;
        return 1;
    }

    if(rule_port[0] == '!')
    {
        *not_flag = 1;
        rule_port++;
    }

    if(rule_port[0] == ':')
    {
        *lo_port = 0;
    }

    toks = mSplit(rule_port, ":", 2, &num_toks, 0);

    switch(num_toks)
    {
        case 1:
            *hi_port = ConvPort(toks[0], proto);

            if(rule_port[0] == ':')
            {
                *lo_port = 0;
            }
            else
            {
                *lo_port = *hi_port;

                if(index(rule_port, ':') != NULL)
                {
                    *hi_port = 65535;
                }
            }

            break;

        case 2:
            *lo_port = ConvPort(toks[0], proto);

            if(toks[1][0] == 0)
                *hi_port = 65535;
            else
                *hi_port = ConvPort(toks[1], proto);

            break;

        default:
            FatalError("%s(%d) => port conversion failed on \"%s\"\n",
                       file_name, file_line, rule_port);
    }

    mSplitFree(&toks, num_toks);

    return 0;
}


/****************************************************************************
 *
 * Function: ConvPort(char *, char *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: port => port string
 *            proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/
int ConvPort(char *port, char *proto)
{
    int conv;           /* storage for the converted number */
    char *digit;      /* used to check for a number */
    struct servent *service_info;

    /*
     * convert a "word port" (http, ftp, imap, whatever) to its corresponding
     * numeric port value
     */
    if(isalpha((int) port[0]) != 0)
    {
        service_info = getservbyname(port, proto);

        if(service_info != NULL)
        {
            conv = ntohs(service_info->s_port);
            return conv;
        }
        else
        {
            FatalError("%s(%d) => getservbyname() failed on \"%s\"\n",
                       file_name, file_line, port);
        }
    }
    digit = port;
    while (*digit) {

        if(!isdigit((int) *digit))
        {
            FatalError("%s(%d) => Invalid port: %s\n", file_name,
                       file_line, port);
        }
        digit++;
    }
    /* convert the value */
    conv = atoi(port);

    /* make sure it's in bounds */
    if((conv >= 0) && (conv < 65536))
    {
        return conv;
    }
    else
    {
        FatalError("%s(%d) => bad port number: %s\n", file_name,
                   file_line, port);
    }

    return 0;
}



/****************************************************************************
 *
 * Function: ParseMessage(char *)
 *
 * Purpose: Stuff the alert message onto the rule
 *
 * Arguments: msg => the msg string
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseMessage(char *msg)
{
    char *ptr;
    char *end;
    int size;
    int count = 0;
    char *read;
    char *write;

    /* figure out where the message starts */
    ptr = index(msg, '"');

    if(ptr == NULL)
    {
        ptr = msg;
    }
    else
        ptr++;

    end = index(ptr, '"');

    if(end != NULL)
        *end = 0;

    while(isspace((int) *ptr))
        ptr++;


    read = write = ptr;

    while(read < end)
    {
        if(*read == '\\')
        {
            read++;
	    count++;

            if(read >= end)
            {
                break;
            }
        }

        *write++ = *read++;
    }

    if(end)
    {
        *(end - count) = '\x0';
    }

    /* find the end of the alert string */
    size = strlen(msg) + 1;
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Message: %s\n", msg););

    /* alloc space for the string and put it in the rule */
    if(size > 0)
    {
        otn_tmp->sigInfo.message = strdup(ptr);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Rule message set to: %s\n", 
				otn_tmp->sigInfo.message););

    }
    else
    {
        ErrorMessage("%s(%d): bad alert message size %d\n", file_name, 
                     file_line, size);
    }

    return;
}



/****************************************************************************
 *
 * Function: ParseLogto(char *)
 *
 * Purpose: stuff the special log filename onto the proper rule option
 *
 * Arguments: filename => the file name
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseLogto(char *filename)
{
    char *sptr;
    char *eptr;

    /* grab everything between the starting " and the end one */
    sptr = index(filename, '"');
    eptr = strrchr(filename, '"');

    if(sptr != NULL && eptr != NULL)
    {
        /* increment past the first quote */
        sptr++;

        /* zero out the second one */
        *eptr = 0;
    }
    else
    {
        sptr = filename;
    }

    /* malloc up a nice shiny clean buffer */
    otn_tmp->logto = (char *) calloc(strlen(sptr) + 1, sizeof(char));

    bzero((char *) otn_tmp->logto, strlen(sptr) + 1);

    strncpy(otn_tmp->logto, sptr, strlen(sptr)+1);

    return;
}




/****************************************************************************
 *
 * Function: ParseActivates(char *)
 *
 * Purpose: Set an activation link record
 *
 * Arguments: act_num => rule number to be activated
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseActivates(char *act_num)
{
    /*
     * allocate a new node on the RTN get rid of whitespace at the front of
     * the list
     */
    while(!isdigit((int) *act_num))
        act_num++;

    otn_tmp->activates = atoi(act_num);

    return;
}




/****************************************************************************
 *
 * Function: ParseActivatedBy(char *)
 *
 * Purpose: Set an activation link record
 *
 * Arguments: act_by => rule number to be activated
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseActivatedBy(char *act_by)
{
    ActivateList *al_ptr;

    al_ptr = rtn_tmp->activate_list;

    if(al_ptr == NULL)
    {
        rtn_tmp->activate_list = (ActivateList *) calloc(sizeof(ActivateList), sizeof(char));

        if(rtn_tmp->activate_list == NULL)
        {
            FatalError("ParseActivatedBy() calloc failed: %s\n", strerror(errno));
        }

        al_ptr = rtn_tmp->activate_list;
    }
    else
    {
        while(al_ptr->next != NULL)
        {
            al_ptr = al_ptr->next;
        }

        al_ptr->next = (ActivateList *) calloc(sizeof(ActivateList), sizeof(char));

        al_ptr = al_ptr->next;

        if(al_ptr == NULL)
        {
            FatalError("ParseActivatedBy() calloc failed: %s\n", strerror(errno));
        }
    }

    /* get rid of whitespace at the front of the list */
    while(!isdigit((int) *act_by))
        act_by++;

    /* set the RTN list node number */
    al_ptr->activated_by = atoi(act_by);

    /* set the OTN list node number */
    otn_tmp->activated_by = atoi(act_by);

    return;
}



void ParseCount(char *num)
{
    while(!isdigit((int) *num))
        num++;

    otn_tmp->activation_counter = atoi(num);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Set activation counter to %d\n", otn_tmp->activation_counter););

    return;
}




/****************************************************************************
 *
 * Function: XferHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Transfer the rule block header data from point A to point B
 *
 * Arguments: rule => the place to xfer from
 *            rtn => the place to xfer to
 *
 * Returns: void function
 *
 ***************************************************************************/
void XferHeader(RuleTreeNode * rule, RuleTreeNode * rtn)
{
    rtn->type = rule->type;
    rtn->sip = rule->sip;
    rtn->dip = rule->dip;
    rtn->hsp = rule->hsp;
    rtn->lsp = rule->lsp;
    rtn->hdp = rule->hdp;
    rtn->ldp = rule->ldp;
    rtn->flags = rule->flags;
    rtn->not_sp_flag = rule->not_sp_flag;
    rtn->not_dp_flag = rule->not_dp_flag;
}



/****************************************************************************
 *
 * Function: TestHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Check to see if the two header blocks are identical
 *
 * Arguments: rule => uh
 *            rtn  => uuuuhhhhh....
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int TestHeader(RuleTreeNode * rule, RuleTreeNode * rtn)
{
    IpAddrSet *rule_idx;  /* ip struct indexer */
    IpAddrSet *rtn_idx;   /* ip struct indexer */

    rtn_idx = rtn->sip;
    for(rule_idx = rule->sip; rule_idx != NULL; rule_idx = rule_idx->next)
    {
        if(rtn_idx && (rtn_idx->ip_addr == rule_idx->ip_addr) &&
                (rtn_idx->netmask == rule_idx->netmask) &&
                (rtn_idx->addr_flags == rule_idx->addr_flags))
        {
            rtn_idx = rtn_idx->next;
        }
        else
        {
            return 0;
        }
    }

    rtn_idx = rtn->dip;
    for(rule_idx = rule->dip ; rule_idx != NULL; rule_idx = rule_idx->next)
    {
        if(rtn_idx && (rtn_idx->ip_addr == rule_idx->ip_addr) &&
                (rtn_idx->netmask == rule_idx->netmask) &&
                (rtn_idx->addr_flags == rule_idx->addr_flags))
        {
            rtn_idx = rtn_idx->next;
        }
        else
        {
            return 0;
        }
    }

    if(rtn->hsp == rule->hsp)
    {
        if(rtn->lsp == rule->lsp)
        {
            if(rtn->hdp == rule->hdp)
            {
                if(rtn->ldp == rule->ldp)
                {
                    if(rtn->flags == rule->flags)
                    {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}


/****************************************************************************
 *
 * Function: VarAlloc()
 *
 * Purpose: allocates memory for a variable
 *
 * Arguments: none
 *
 * Returns: pointer to new VarEntry
 *
 ***************************************************************************/
struct VarEntry *VarAlloc()
{
    struct VarEntry *new;

    if((new = (struct VarEntry *) calloc(sizeof(struct VarEntry), sizeof(char))) == NULL)
    {
        FatalError("cannot allocate memory for VarEntry.");
    }

    return(new);
}

/****************************************************************************
 *
 * Function: VarDefine(char *, char *)
 *
 * Purpose: define the contents of a variable
 *
 * Arguments: name => the name of the variable
 *            value => the contents of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
struct VarEntry *VarDefine(char *name, char *value)
{
    struct VarEntry *p;

    if(value == NULL)
    {
        FatalError("%s(%d):  Bad value in variable definition!\n"
                   "Make sure you don't have a \"$\" in the var name\n",
                   file_name, file_line);
    }

    if(!VarHead)
    {
        p = VarAlloc();
        p->name = strdup(name);
        p->value = strdup(value);
        p->prev = p;
        p->next = p;

        VarHead = p;

        return p;
    }
    p = VarHead;

    do
    {
        if(strcasecmp(p->name, name) == 0)
        {
	    if (!(p->flags & VAR_STATIC))
            {
                if( p->value )
                    free(p->value);
                
                p->value = strdup(value);
            }
	    return (p);
        }
        p = p->next;

    } while(p != VarHead);

    p = VarAlloc();
    p->name = strdup(name);
    p->value = strdup(value);
    p->prev = VarHead;
    p->next = VarHead->next;
    p->next->prev = p;
    VarHead->next = p;
    
    return p;
}


/****************************************************************************
 *
 * Function: VarDelete(char *)
 *
 * Purpose: deletes a defined variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
void VarDelete(char *name)
{
    struct VarEntry *p;


    if(!VarHead)
        return;

    p = VarHead;

    do
    {
        if(strcasecmp(p->name, name) == 0)
        {
            p->prev->next = p->next;
            p->next->prev = p->prev;

            if(VarHead == p)
                if((VarHead = p->next) == p)
                    VarHead = NULL;

            if(p->name)
                free(p->name);

            if(p->value)
                free(p->value);

            free(p);

            return;
        }
        p = p->next;

    } while(p != VarHead);
}


/****************************************************************************
 *
 * Function: VarGet(char *)
 *
 * Purpose: get the contents of a variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: char * to contents of variable or FatalErrors on an
 *          undefined variable name
 *
 ***************************************************************************/
char *VarGet(char *name)
{
    struct VarEntry *p;


    if(VarHead)
    {
        p = VarHead;

        do
        {
            if(strcasecmp(p->name, name) == 0)
                return(p->value);

            p = p->next;

        } while(p != VarHead);
    }

    FatalError("Undefined variable name: (%s:%d): %s\n", 
               file_name, file_line, name);
    
    
    return NULL;
}

/****************************************************************************
 *
 * Function: ExpandVars(char *)
 *
 * Purpose: expand all variables in a string
 *
 * Arguments: string => the name of the variable
 *
 * Returns: char * to the expanded string
 *
 ***************************************************************************/
char *ExpandVars(char *string)
{
    static char estring[PARSERULE_SIZE];
    char rawvarname[128], varname[128], varaux[128], varbuffer[128], varmodifier, *varcontents;
    int varname_completed, c, i, j, iv, jv, l_string, name_only;
    int quote_toggle = 0;

    if(!string || !*string || !strchr(string, '$'))
        return(string);

    bzero((char *) estring, sizeof(estring));

    i = j = 0;
    l_string = strlen(string);
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "ExpandVars, Before: %s\n", string););

    while(i < l_string && j < sizeof(estring) - 1)
    {
        c = string[i++];
        
        if(c == '"')
        {
            /* added checks to make sure that we are inside a quoted string
             */
            quote_toggle ^= 1;
        }

        if(c == '$' && !quote_toggle)
        {
            bzero((char *) rawvarname, sizeof(rawvarname));
            varname_completed = 0;
            name_only = 1;
            iv = i;
            jv = 0;

            if(string[i] == '(')
            {
                name_only = 0;
                iv = i + 1;
            }

            while(!varname_completed
                  && iv < l_string
                  && jv < sizeof(rawvarname) - 1)
            {
                c = string[iv++];

                if((name_only && !(isalnum(c) || c == '_'))
                   || (!name_only && c == ')'))
                {
                    varname_completed = 1;

                    if(name_only)
                        iv--;
                }
                else
                {
                    rawvarname[jv++] = c;
                }
            }

            if(varname_completed || iv == l_string)
            {
                char *p;

                i = iv;

                varcontents = NULL;

                bzero((char *) varname, sizeof(varname));
                bzero((char *) varaux, sizeof(varaux));
                varmodifier = ' ';

                if((p = strchr(rawvarname, ':')))
                {
                    strncpy(varname, rawvarname, p - rawvarname);

                    if(strlen(p) >= 2)
                    {
                        varmodifier = *(p + 1);
                        strcpy(varaux, p + 2);
                    }
                }
                else
                    strcpy(varname, rawvarname);

                bzero((char *) varbuffer, sizeof(varbuffer));

                varcontents = VarGet(varname);

                switch(varmodifier)
                {
                    case '-':
                        if(!varcontents || !strlen(varcontents))
                            varcontents = varaux;
                        break;

                    case '?':
                        if(!varcontents || !strlen(varcontents))
                        {
                            ErrorMessage("%s(%d): ", file_name, file_line);

                            if(strlen(varaux))
                                FatalError("%s\n", varaux);
                            else
                                FatalError("Undefined variable \"%s\"\n", varname);
                        }
                        break;
                }

                if(varcontents)
                {
                    int l_varcontents = strlen(varcontents);

                    iv = 0;

                    while(iv < l_varcontents && j < sizeof(estring) - 1)
                        estring[j++] = varcontents[iv++];
                }
            }
            else
            {
                estring[j++] = '$';
            }
        }
        else
        {
            estring[j++] = c;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "ExpandVars, After: %s\n", estring););

    return(estring);
}



/******************************************************************
 *
 * Function: LinkDynamicRules()
 *
 * Purpose: Move through the activation and dynamic lists and link
 *          the activation rules to the rules that they activate.
 *
 * Arguments: None
 *
 * Returns: void function
 *
 ******************************************************************/
void LinkDynamicRules()
{
    SetLinks(Activation.TcpList, Dynamic.TcpList);
    SetLinks(Activation.UdpList, Dynamic.UdpList);
    SetLinks(Activation.IcmpList, Dynamic.IcmpList);
}




/******************************************************************
 *
 * Function: SetLinks()
 *
 * Purpose: Move through the activation and dynamic lists and link
 *          the activation rules to the rules that they activate.
 *
 * Arguments: activator => the activation rules
 *            activatee => the rules being activated
 *
 * Returns: void function
 *
 ******************************************************************/
void SetLinks(RuleTreeNode * activator, RuleTreeNode * activated_by)
{
    RuleTreeNode *act_idx;
    RuleTreeNode *dyn_idx;
    OptTreeNode *act_otn_idx;

    act_idx = activator;
    dyn_idx = activated_by;

    /* walk thru the RTN list */
    while(act_idx != NULL)
    {
        if(act_idx->down != NULL)
        {
            act_otn_idx = act_idx->down;

            while(act_otn_idx != NULL)
            {
                act_otn_idx->RTN_activation_ptr = GetDynamicRTN(act_otn_idx->activates, dyn_idx);

                if(act_otn_idx->RTN_activation_ptr != NULL)
                {
                    act_otn_idx->OTN_activation_ptr = GetDynamicOTN(act_otn_idx->activates, act_otn_idx->RTN_activation_ptr);
                }
                act_otn_idx = act_otn_idx->next;
            }
        }
        act_idx = act_idx->right;
    }
}



RuleTreeNode *GetDynamicRTN(int link_number, RuleTreeNode * dynamic_rule_tree)
{
    RuleTreeNode *rtn_idx;
    ActivateList *act_list;

    rtn_idx = dynamic_rule_tree;

    while(rtn_idx != NULL)
    {
        act_list = rtn_idx->activate_list;

        while(act_list != NULL)
        {
            if(act_list->activated_by == link_number)
            {
                return rtn_idx;
            }
            act_list = act_list->next;
        }

        rtn_idx = rtn_idx->right;
    }

    return NULL;
}




OptTreeNode *GetDynamicOTN(int link_number, RuleTreeNode * dynamic_rule_tree)
{
    OptTreeNode *otn_idx;

    otn_idx = dynamic_rule_tree->down;

    while(otn_idx != NULL)
    {
        if(otn_idx->activated_by == link_number)
        {
            return otn_idx;
        }
        otn_idx = otn_idx->next;
    }

    return NULL;
}


/****************************************************************************
 *
 * Function: ProcessAlertFileOption(char *)
 *
 * Purpose: define the alert file
 *
 * Arguments: filespec => the file specification
 *
 * Returns: void function
 *
 ***************************************************************************/
void ProcessAlertFileOption(char *filespec)
{
    pv.alert_filename = ProcessFileOption(filespec);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"alertfile set to: %s\n", 
                pv.alert_filename););
    return;
}

char *ProcessFileOption(char *filespec)
{
    char *filename;
    char buffer[STD_BUF];

    if(filespec == NULL)
    {
        FatalError("no arguement in this file option, remove extra ':' at the end of the alert option\n");
    }

    /* look for ".." in the string and complain and exit if it is found */
    if(strstr(filespec, "..") != NULL)
    {
        FatalError("file definition contains \"..\".  Do not do that!\n");
    }

    if(filespec[0] == '/')
    {
        /* absolute filespecs are saved as is */
        filename = strdup(filespec);
    }
    else
    {
        /* relative filespec is considered relative to the log directory */
        /* or /var/log if the log directory has not been set */
        if(pv.log_dir)
        {
            strlcpy(buffer, pv.log_dir, STD_BUF);
        }
        else
        {
            strlcpy(buffer, "/var/log/snort", STD_BUF);
        }

        strlcat(buffer, "/", STD_BUF - strlen(buffer));
        strlcat(buffer, filespec, STD_BUF - strlen(buffer));
        filename = strdup(buffer);
    }

    if(!pv.quiet_flag)
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ProcessFileOption: %s\n", filename););

    return filename;
}

void ProcessFlowbitsSize(char **args, int nargs)
{
    int i;
    char *pcEnd;

    if(nargs)
    {
        i = strtol(args[0], &pcEnd, 10);
        if(*pcEnd || i < 0 || i > 256)
        {
            FatalError("%s(%d) => Invalid argument to 'flowbits_size'.  "  
                       "Must be a positive integer and less than 256.\n",
                       file_name, file_line);
        }
        
        giFlowbitSize = (unsigned int)i;
    }

    return;
}

void ProcessEventQueue(char **args, int nargs)
{
    int iCtr;

    for(iCtr = 0; iCtr < nargs; iCtr++)
    {
        if(!strcasecmp("max_queue", args[iCtr]))
        {
            iCtr++;
            if(iCtr < nargs)
            {
                g_event_queue.max_events = atoi(args[iCtr]);
                if(g_event_queue.max_events <= 0)
                {
                    FatalError("%s(%d) => Invalid argument to 'max_queue'.  "
                               "Must be a positive integer.\n", file_name,
                               file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => No argument to 'max_queue'.  "
                           "Argument must be a positive integer.\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp("log", args[iCtr]))
        {
            iCtr++;
            if(iCtr < nargs)
            {
                g_event_queue.log_events = atoi(args[iCtr]);
                if(g_event_queue.log_events <= 0)
                {
                    FatalError("%s(%d) => Invalid argument to 'log'.  "
                               "Must be a positive integer.\n", file_name,
                               file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => No argument to 'log'.  "
                           "Argument must be a positive integer.\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp("order_events", args[iCtr]))
        {
            iCtr++;
            if(iCtr < nargs)
            {
                if(!strcasecmp("priority", args[iCtr]))
                {
                    g_event_queue.order = SNORT_EVENTQ_PRIORITY;
                }
                else if(!strcasecmp("content_length", args[iCtr]))
                {
                    g_event_queue.order = SNORT_EVENTQ_CONTENT_LEN;
                }
            }
            else
            {
                FatalError("%s(%d) => No argument to 'order_events'.  "
                           "Arguments may be either 'priority' or "
                           "content_length.\n",
                           file_name, file_line);
            }
        }
        else
        {
            FatalError("%s(%d) => Invalid argument to 'event_queue'.  "
                       "To configure event_queue, the options 'max_queue', "
                       "'log', and 'order_events' must be configured.\n",
                       file_name, file_line);
        }
    }
    
    return;
}

void ProcessDetectionOptions( char ** args, int nargs )
{
	int i;
    
	for(i=0;i<nargs;i++)
	{
	   if( !strcasecmp(args[i],"search-method") )
	   {
	       i++;
	       if( i < nargs ) 
           {
               if(fpSetDetectSearchMethod(args[i]))
               {
                   FatalError("%s (%d)=> Invalid argument to 'search-method'"
                              ".  Must be either 'mwm' or 'ac'.\n",
                              file_name, file_line);
               }
           }
           else
           {
               FatalError("%s (%d)=> No argument to 'search-method'. "
                          "Must be either 'mwm' or 'ac'.\n",
                          file_name, file_line);
           }
	   }
       else if(!strcasecmp(args[i], "debug"))
       {
           fpSetDebugMode();
       }
       else if(!strcasecmp(args[i], "no_stream_inserts"))
       {
           fpSetStreamInsert();
       }
       else if(!strcasecmp(args[i], "max_queue_events"))
       {
           i++;
           if(i < nargs)
           {
               if(fpSetMaxQueueEvents(atoi(args[i])))
               {
                   FatalError("%s (%d)=> Invalid argument to "
                              "'max_queue_events'.  Argument must "
                              "be greater than 0.\n",
                              file_name, file_line);
               }
           }
       }
       else
       {
           FatalError("%s (%d)=> '%s' is an invalid option to the "
                      "'config detection:' configuration.\n", 
                      file_name, file_line, args[i]);
       }
    }
}

void ProcessResetMac(char ** args, int nargs)
{
#ifdef GIDS
#ifndef IPFW

    int i = 0;
    int num_macargs=nargs; 
    char **macargs;

    macargs = mSplit(args[0], ":", 6, &num_macargs, '\\');

    if(num_macargs != 6)
    {
	FatalError("%s (%d)=> '%s' is not a valid macaddress "
	           "for layer2resets\n",
		   file_name, file_line, args[0]);
    }

    for(i = 0; i < num_macargs; i++)
        pv.enet_src[i] = (u_int8_t) strtoul(macargs[i], NULL, 16);

#endif /* IPFW */
#endif /* GIDS */

    return;
} 

void ParseConfig(char *rule)
{
    char ** toks;
    char **rule_toks = NULL;
    char **config_decl = NULL;
    char *args = NULL;
    char *config;
    int num_rule_toks = 0, num_config_decl_toks = 0, num_toks=0;

    rule_toks = mSplit(rule, ":", 2, &num_rule_toks, 0);
    if(num_rule_toks > 1)
    {
        args = rule_toks[1];
    }

    config_decl = mSplit(rule_toks[0], " ", 2, &num_config_decl_toks, '\\');
    if(num_config_decl_toks != 2)
    {
        FatalError("unable to parse config: %s\n", rule);
    }

    config = config_decl[1];

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Config: %s\n", config););
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Args: %s\n", args););

    if(!strcasecmp(config, "order"))
    {
        if(!pv.rules_order_flag)
            OrderRuleLists(args);
        else
	LogMessage("Commandline option overiding rule file config\n");
    
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
	
        return;
    }
    else if(!strcasecmp(config, "alertfile"))
    {
        toks = mSplit(args, " ", 1, &num_toks, 0);

        ProcessAlertFileOption(toks[0]);
	
        mSplitFree( &toks, num_toks );
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "classification"))
    {
        ParseClassificationConfig(args);
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "detection"))
    {
        toks = mSplit(args, ", ",20, &num_toks, 0);
        ProcessDetectionOptions(toks,num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "flowbits_size"))
    {
        toks = mSplit(args, ", ",20, &num_toks, 0);
        ProcessFlowbitsSize(toks, num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "event_queue"))
    {
        toks = mSplit(args, ", ", 20, &num_toks, 0);
        ProcessEventQueue(toks, num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "layer2resets"))
    {   
        if(args)
        {
            toks = mSplit(args, " ", 1, &num_toks, 0);
            ProcessResetMac(toks, num_toks);

            mSplitFree( &toks, num_toks );
        }

#ifdef GIDS
#ifndef IPFW

        pv.layer2_resets = 1;

#endif
#endif

        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);

        return;
        
    }
    else if(!strcasecmp(config, "asn1"))
    {
        toks = mSplit(args, ", ", 20, &num_toks, 0);

        if(num_toks > 0)
        {
            if(asn1_init_mem(atoi(toks[0])))
            {
                FatalError("%s(%d) => Invalid argument to 'asn1' "
                           "configuration.  Must be a positive integer.\n", 
                           file_name, file_line);
            }
        }
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_chars_only"))
    {
        /* dump the application layer as text only */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Character payload dump set\n"););
        pv.char_data_flag = 1;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_payload"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Payload dump set\n"););
        pv.data_flag = 1;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_decode_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the decoder alerts\n"););
        pv.decoder_flags.decode_alerts = 0;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_decode_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of decoder alerts\n"););
        pv.decoder_flags.drop_alerts = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_tcpopt_experimental_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the tcpopt experimental alerts\n"););
        pv.decoder_flags.tcpopt_experiment = 0;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_tcpopt_experimental_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of tcpopt exprimental alerts\n"););
        pv.decoder_flags.drop_tcpopt_experiment = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              

    else if(!strcasecmp(config, "disable_tcpopt_obsolete_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the tcpopt obsolete alerts\n"););
        pv.decoder_flags.tcpopt_obsolete = 0;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_tcpopt_obsolete_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of tcpopt obsolete alerts\n"););
        pv.decoder_flags.drop_tcpopt_obsolete = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              

    else if(!strcasecmp(config, "disable_ttcp_alerts") ||
            !strcasecmp(config, "disable_tcpopt_ttcp_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the ttcp alerts\n"););
        pv.decoder_flags.tcpopt_ttcp = 0;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_ttcp_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of ttcp alerts\n"););
        pv.decoder_flags.drop_tcpopt_ttcp = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              

    else if(!strcasecmp(config, "disable_tcpopt_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the all the other tcpopt alerts\n"););
        pv.decoder_flags.tcpopt_decode = 0;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_tcpopt_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of all other tcpopt alerts\n"););
        pv.decoder_flags.drop_tcpopt_decode = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              

    else if(!strcasecmp(config, "disable_ipopt_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the all the ipopt alerts\n"););
        pv.decoder_flags.ipopt_decode = 0;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_ipopt_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of all the ipopt alerts\n"););
        pv.decoder_flags.drop_ipopt_decode = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              

    else if(!strcasecmp(config, "decode_data_link"))
    {
        /* dump the data link layer as text only */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Decode DLL set\n"););
        pv.show2hdr_flag = 1;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "bpf_file"))
    {
        /* Read BPF filters from a file */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "BPF file set\n"););
        /* suck 'em in */
        pv.pcap_cmd = read_infile(args);
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "set_gid"))
    {
#ifdef WIN32
        FatalError(" Setting the group id is not supported in the WIN32 port of snort!\n");
#else
        if((groupname = calloc(strlen(args) + 1, 1)) == NULL)
            FatalPrintError("calloc");

        bcopy(args, groupname, strlen(args));

        if((groupid = atoi(groupname)) == 0)
        {
            gr = getgrnam(groupname);

            if(gr == NULL)
            {
                ErrorMessage("%s(%d) => Group \"%s\" unknown\n", 
                             file_name, file_line, groupname);
            }

            groupid = gr->gr_gid;
        }
#endif
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);

        return;
    }
    else if(!strcasecmp(config, "daemon"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Daemon mode flag set\n"););
        pv.daemon_flag = 1;
        flow_set_daemon();
        pv.quiet_flag = 1;
	
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;

    }
    else if(!strcasecmp(config, "reference_net"))
    {
        GenHomenet(args);
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "threshold"))
    {
        ProcessThresholdOptions(args);
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "interface"))
    {
        pv.interface = (char *) malloc(strlen(args) + 1);   /* XXX OOM check */
        strlcpy(pv.interface, args, strlen(args)+1);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Interface = %s\n", 
                    PRINT_INTERFACE(pv.interface)););

        if(!pv.readmode_flag)
        {
            if(pd != NULL)
            {
                pcap_close(pd);
            }

            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Opening interface: %s\n", 
                        PRINT_INTERFACE(pv.interface)););
            /* open up our libpcap packet capture interface */
            OpenPcap();
        }
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "alert_with_interface_name"))
    {
        pv.alert_interface_flag = 1;
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "logdir"))
    {
        LogMessage("Found logdir config directive (%s)\n", args);
        if(!(pv.log_dir = strdup(args)))
            FatalError("Out of memory setting log dir from config file\n");
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Log directory = %s\n", 
                    pv.log_dir););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "chroot"))
    {
        LogMessage("Found chroot config directive (%s)\n", args);
        if(!(pv.chroot_dir = strdup(args)))
            FatalError("Out of memory setting chroot dir from config file\n");
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Chroot directory = %s\n",
                    pv.chroot_dir););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "umask"))
    {
        char *p;
        long val = 0;
        int umaskchange = 1;
        int defumask = 0;

        umaskchange = 0;

        val = strtol(args, &p, 8);
        if (*p != '\0' || val < 0 || (val & ~FILEACCESSBITS))
        {
            FatalError("bad umask %s\n", args);
        }
        else
        {
            defumask = val;
        }

        /* if the umask arg happened, set umask */
        if (umaskchange)
        {
            umask(077);           /* set default to be sane */
        }
        else
        {
            umask(defumask);
        }
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "pkt_count"))
    {
        pv.pkt_cnt = atoi(args);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Exiting after %d packets\n", pv.pkt_cnt););
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "nolog"))
    {
        pv.log_mode = LOG_NONE;
        pv.log_cmd_override = 1;    /* XXX this is a funky way to do things */
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "obfuscate"))
    {
        pv.obfuscation_flag = 1;
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "no_promisc"))
    {
        pv.promisc_flag = 0;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Promiscuous mode disabled!\n"););
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "snaplen"))
    {
        pv.pkt_snaplen = atoi(args);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Snaplength of Packets set to: %d\n", 
                    pv.pkt_snaplen););
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "quiet"))
    {
        pv.quiet_flag = 1;
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "read_bin_file"))
    {
        strlcpy(pv.readfile, args, STD_BUF);
        pv.readmode_flag = 1;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Opening file: %s\n", pv.readfile););

        /* open the packet file for readback */
        OpenPcap();
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "checksum_mode"))
    {
	int num_atoks,i;
	char **atoks;

        atoks  = mSplit(args, " ",10 , &num_atoks, 0);
	
	for(i=0;i<num_atoks;i++)
	{
        args=atoks[i];

        if(args == NULL || !strcasecmp(args, "all"))
        {
            pv.checksums_mode = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;
        }
        else if(!strcasecmp(args, "none"))
        {
            pv.checksums_mode = 0;
        }

	else if(!strcasecmp(args, "noip")) 
        {
            pv.checksums_mode ^= DO_IP_CHECKSUMS;
        }
	else if(!strcasecmp(args, "notcp"))
        {
            pv.checksums_mode ^= DO_TCP_CHECKSUMS;
        }
	else if(!strcasecmp(args, "noudp"))
        {
            pv.checksums_mode ^= DO_UDP_CHECKSUMS;
        }
	else if(!strcasecmp(args, "noicmp"))
        {
            pv.checksums_mode ^= DO_ICMP_CHECKSUMS;
        }

	else if(!strcasecmp(args, "ip")) 
        {
            pv.checksums_mode |= DO_IP_CHECKSUMS;
        }
	else if(!strcasecmp(args, "tcp"))
        {
            pv.checksums_mode |= DO_TCP_CHECKSUMS;
        }
	else if(!strcasecmp(args, "udp"))
        {
            pv.checksums_mode |= DO_UDP_CHECKSUMS;
        }
	else if(!strcasecmp(args, "icmp"))
        {
            pv.checksums_mode |= DO_ICMP_CHECKSUMS;
        }
	
	}
	
	mSplitFree(&atoks,num_atoks);
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "set_uid"))
    {
#ifdef WIN32
        FatalError("Setting the user id is not supported in the WIN32 port of snort!\n");
#else
        if((username = calloc(strlen(args) + 1, 1)) == NULL)
            FatalPrintError("malloc");

        bcopy(args, username, strlen(args));

        if((userid = atoi(username)) == 0)
        {
            pw = getpwnam(username);
            if(pw == NULL)
                FatalError("User \"%s\" unknown\n", username);

            userid = pw->pw_uid;
        }
        else
        {
            pw = getpwuid(userid);
            if(pw == NULL)
                FatalError(
                        "Can not obtain username for uid: %lu\n",
                        (u_long) userid);
        }

        if(groupname == NULL)
        {
            char name[256];

            snprintf(name, 255, "%lu", (u_long) pw->pw_gid);

            if((groupname = calloc(strlen(name) + 1, 1)) == NULL)
            {
                FatalPrintError("malloc");
            }
            groupid = pw->pw_gid;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "UserID: %lu GroupID: %lu\n",
                    (unsigned long) userid, (unsigned long) groupid););
#endif
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "utc"))
    {
        pv.use_utc = 1;
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "verbose"))
    {
        pv.verbose_flag = 1;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose Flag active\n"););
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_payload_verbose"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
                    "Verbose packet bytecode dumps enabled\n"););

        pv.verbose_bytedump_flag = 1;
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "show_year"))
    {
        pv.include_year = 1;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n"););
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "stateful")) /* this one's for Johnny! */
    {
        pv.assurance_mode = ASSURE_EST;
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "min_ttl"))
    {
        if(args)
        {
            pv.min_ttl = atoi(args);
        }
        else 
        {
            FatalError("config min_ttl requires an argument\n");
        }
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "reference"))
    {
        if(args)
        {
            ParseReferenceSystemConfig(args);
        }
        else
        {
            ErrorMessage("%s(%d) => Reference config without "
                         "arguments\n", file_name, file_line);
        }
	mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }

    FatalError("Unknown config directive: %s\n", rule);
	

    return;
}

/* verify that we are not reusing some other keyword */
int checkKeyword(char *keyword)
{
    RuleListNode *node = RuleLists;

    if(RuleType(keyword) != RULE_UNKNOWN)
    {
        return 1;
    }

    /* check the declared ruletypes now */
    while(node != NULL)
    {
        if(!strcasecmp(node->name, keyword))
        {
            return 1;
        }

        node = node->next;
    }

    return 0;
}

void ParseRuleTypeDeclaration(FILE* rule_file, char *rule)
{
    char *input;
    char *keyword;
    char **toks;
    int num_toks;
    int type;
    int rval = 1;
    ListHead *listhead = NULL;

    toks = mSplit(rule, " ", 10, &num_toks, 0);
    keyword = strdup(toks[1]);

    /* Verify keyword is unique */
    if(checkKeyword(keyword))
    {
        FatalError("%s(%d): Duplicate keyword: %s\n",
                   file_name, file_line, keyword);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Declaring new rule type: %s\n", keyword););

    if(num_toks > 2)
    {
        if(strcasecmp("{", toks[2]) != 0)
        {
            FatalError("%s(%d): Syntax error: %s\n",
                       file_name, file_line, rule);
        }
    }
    else
    {
        input = ReadLine(rule_file);
        free(input);
    }

    input = ReadLine(rule_file);

    mSplitFree(&toks, num_toks);

    toks = mSplit(input, " ", 10, &num_toks, 0);

    /* read the type field */
    if(!strcasecmp("type", toks[0]))
    {
        type = RuleType(toks[1]);
        /* verify it is a valid ruletype */
        if((type != RULE_LOG) && (type != RULE_PASS) && (type != RULE_ALERT) &&
           (type != RULE_ACTIVATE) && (type != RULE_DYNAMIC))
        {
            FatalError("%s(%d): Invalid type for rule type declaration: %s\n", file_name, file_line, toks[1]);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"\ttype(%i): %s\n", type, toks[1]););

        if(type == RULE_PASS)
        {
            rval = 0;
        }

        listhead = CreateRuleType(keyword, type, rval, NULL);
    }
    else
    {
        FatalError("%s(%d): Type not defined for rule file declaration: %s\n", file_name, file_line, keyword);
    }

    free(input);
    input = ReadLine(rule_file);
    
    mSplitFree(&toks, num_toks);


    toks = mSplit(input, " ", 2, &num_toks, 0);

    while(strcasecmp("}", toks[0]) != 0)
    {
        if(RuleType(toks[0]) != RULE_OUTPUT)
        {
            FatalError("%s(%d): Not an output plugin declaration: %s\n", file_name, file_line, keyword);
        }

        head_tmp = listhead;
        ParseOutputPlugin(input);
        head_tmp = NULL;
        free(input);
        input = ReadLine(rule_file);

        mSplitFree(&toks, num_toks);
        toks = mSplit(input, " ", 2, &num_toks, 0);
    }

    mSplitFree(&toks, num_toks);

    pv.num_rule_types++;

    return;
}

/* adapted from ParseRuleFule in rules.c */
char *ReadLine(FILE * file)
{
    char buf[STD_BUF];
    char *index;

    bzero((char *) buf, STD_BUF);

    /*
     * Read a line from file and return it. Skip over lines beginning with #,
     * ;, or a newline
     */
    while((fgets(buf, STD_BUF, file)) != NULL)
    {
        file_line++;
        index = buf;

#ifdef DEBUG2
	LogMessage("Got line %s (%d): %s\n", file_name, file_line, buf);
#endif
        /* if it's not a comment or a <CR>, we return it */
        if((*index != '#') && (*index != 0x0a) && (*index != ';')
           && (index != NULL))
        {
            /* advance through any whitespace at the beginning of ther line */
            while(isspace((int) *index))
                ++index;

            /* return a copy of the line */
            return strdup(index);
        }
    }

    return NULL;
}

/*
 * Same as VarGet - but this does not Fatal out if a var is not found
 */
char *VarSearch(char *name)
{
    struct VarEntry *p;
    if(VarHead)
    {
        p = VarHead;
        do
        {
            if(strcasecmp(p->name, name) == 0)
                return p->value;
            p = p->next;
        } while(p != VarHead);
    }

    return NULL;
}
