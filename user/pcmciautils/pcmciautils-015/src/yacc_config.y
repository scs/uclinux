%{
/*
 * Startup tool for non statically mapped PCMCIA sockets - config file parsing
 *
 * (C) 2005		Dominik Brodowski <linux@brodo.de>
 *
 *  The initial developer of the original code is David A. Hinds
 *  <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 *  are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * License: GPL v2
 */
    
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>

#include "startup.h"

/* If bison: generate nicer error messages */ 
#define YYERROR_VERBOSE 1
 
/* from lex_config, for nice error messages */
extern char *current_file;
extern int current_lineno;

void yyerror(char *msg, ...);

%}

%token DEVICE CARD ANONYMOUS TUPLE MANFID VERSION FUNCTION PCI
%token BIND CIS TO NEEDS_MTD MODULE OPTS CLASS
%token REGION JEDEC DTYPE DEFAULT MTD
%token INCLUDE EXCLUDE RESERVE IRQ_NO PORT MEMORY
%token STRING NUMBER SOURCE

%union {
    char *str;
    u_long num;
    struct adjust_list_t *adjust;
}

%type <str> STRING
%type <num> NUMBER
%type <adjust> adjust resource
%%
list:	  /* nothing */
	| list adjust
		{
		    adjust_list_t **tail = &root_adjust;
		    while (*tail != NULL) tail = &(*tail)->next;
		    *tail = $2;
		}
	;

adjust:   INCLUDE resource
		{
		    $2->adj.Action = ADD_MANAGED_RESOURCE;
		    $$ = $2;
		}
	| EXCLUDE resource
		{
		    $2->adj.Action = REMOVE_MANAGED_RESOURCE;
		    $$ = $2;
		}
	| RESERVE resource
		{
		    $2->adj.Action = ADD_MANAGED_RESOURCE;
		    $2->adj.Attributes |= RES_RESERVED;
		    $$ = $2;
		}
	| adjust ',' resource
		{
		    $3->adj.Action = $1->adj.Action;
		    $3->adj.Attributes = $1->adj.Attributes;
		    $3->next = $1;
		    $$ = $3;
		}
	;

resource: IRQ_NO NUMBER
		{
		    $$ = calloc(sizeof(adjust_list_t), 1);
		    $$->adj.Resource = RES_IRQ;
		    $$->adj.resource.irq.IRQ = $2;
		}
	| PORT NUMBER '-' NUMBER
		{
		    if (($4 < $2) || ($4 > 0xffff)) {
			yyerror("invalid port range 0x%x-0x%x", $2, $4);
			YYERROR;
		    }
		    $$ = calloc(sizeof(adjust_list_t), 1);
		    $$->adj.Resource = RES_IO_RANGE;
		    $$->adj.resource.io.BasePort = $2;
		    $$->adj.resource.io.NumPorts = $4 - $2 + 1;
		}
	| MEMORY NUMBER '-' NUMBER
		{
		    if ($4 < $2) {
			yyerror("invalid address range 0x%x-0x%x", $2, $4);
			YYERROR;
		    }
		    $$ = calloc(sizeof(adjust_list_t), 1);
		    $$->adj.Resource = RES_MEMORY_RANGE;
		    $$->adj.resource.memory.Base = $2;
		    $$->adj.resource.memory.Size = $4 - $2 + 1;
		}
	;

%%
void yyerror(char *msg, ...)
{
     va_list ap;
     char str[256];

     va_start(ap, msg);
     sprintf(str, "error in file '%s' line %d: ",
	     current_file, current_lineno);
     vsprintf(str+strlen(str), msg, ap);
#if YYDEBUG
     fprintf(stderr, "%s\n", str);
#else
     syslog(LOG_ERR, "%s", str);
#endif
     va_end(ap);
}

