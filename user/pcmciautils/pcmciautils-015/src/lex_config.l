/* Special state for handling include files */
%x src

%{
/*
 * Startup tool for non statically mapped PCMCIA sockets
 *
 * (C) 2005		Dominik Brodowski <linux@brodo.de>
 *
 *  The initial developer of the original code is David A. Hinds
 *  <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 *  are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * License: GPL v2
 */

#undef src

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#ifdef HAS_WORDEXP
#include <wordexp.h>
#else
#include <glob.h>
#endif

#define src 1

#include "yacc_config.h"

/* For assembling nice error messages */
char *current_file;
int current_lineno;

static int lex_number(char *s);
static int lex_string(char *s);
static void do_source(char *fn);
static int do_eof(void);

%}

int	[0-9]+
hex	0x[0-9a-fA-F]+
str	\"([^"]|\\.)*\"

%%

source[ \t]+	BEGIN(src); return SOURCE;
<src>[^\n]+	do_source(yytext); BEGIN(INITIAL);
<<EOF>>		if (do_eof()) yyterminate();

\n		current_lineno++;
[ \t]*		/* skip */ ;
[ ]*[#;].*	/* skip */ ;

exclude		return EXCLUDE;
include		return INCLUDE;
irq		return IRQ_NO;
port		return PORT;
memory		return MEMORY;
module		/* skip */ ;

{int}		return lex_number(yytext);

{hex}		return lex_number(yytext);

{str}		return lex_string(yytext);

.		return yytext[0];

%%

#ifndef yywrap
int yywrap() { return 1; }
#endif

/*======================================================================

    Stuff to parse basic data types

======================================================================*/

static int lex_number(char *s)
{
    yylval.num = strtoul(s, NULL, 0);
    return NUMBER;
}

static int lex_string(char *s)
{
    int n = strlen(s);
    yylval.str = malloc(n-1);
    strncpy(yylval.str, s+1, n-2);
    yylval.str[n-2] = '\0';
    return STRING;
}

/*======================================================================

    Code to support nesting of configuration files

======================================================================*/

#define MAX_SOURCE_DEPTH 4
struct source_stack {
    YY_BUFFER_STATE	buffer;
    char		*filename;
    int			lineno, fileno;
    FILE		*file;
#ifdef HAS_WORDEXP
    wordexp_t		word;
#else
    glob_t		glob;
#endif
} source_stack[MAX_SOURCE_DEPTH];
static int source_stack_ptr = 0;
static int parse_env = 0;

static int get_glob(void)
{
    struct source_stack *s = &source_stack[source_stack_ptr];
#ifdef HAS_WORDEXP
    while (s->fileno < s->word.we_wordc) {
	char *fn = s->word.we_wordv[s->fileno];
#else
    while (s->fileno < s->glob.gl_pathc) {
	char *fn = s->glob.gl_pathv[s->fileno];
#endif
	s->file = fopen(fn, "r");
	if (s->file == NULL) {
	    if (strpbrk(fn, "?*[") == NULL)
		syslog(LOG_ERR, "could not open '%s': %m", fn);
	    s->fileno++;
	} else {
	    current_lineno = 1;
	    current_file = strdup(fn);
	    yy_switch_to_buffer(yy_create_buffer(s->file, YY_BUF_SIZE));
	    source_stack_ptr++;
	    s->fileno++;
	    return 0;
	}
    }
    return -1;
}

static void do_source(char *fn)
{
    struct source_stack *s = &source_stack[source_stack_ptr];

    if (source_stack_ptr >= MAX_SOURCE_DEPTH) {
	syslog(LOG_ERR, "source depth limit exceeded");
	return;
    }
#ifdef HAS_WORDEXP
    wordexp(fn, &s->word, 0);
#else
    glob(fn, GLOB_NOCHECK, NULL, &s->glob);
#endif
    s->fileno = 0;
    s->buffer = YY_CURRENT_BUFFER;
    s->lineno = current_lineno;
    s->filename = current_file;
    get_glob();
}

static int do_eof(void)
{
    struct source_stack *s = &source_stack[--source_stack_ptr];
    if (source_stack_ptr < 0) {
	if (parse_env == 0) {
	    char *t = getenv("PCMCIA_OPTS");
	    if (t == NULL) return -1;
	    parse_env = 1;
	    source_stack_ptr = 0;
	    current_file = "PCMCIA_OPTS";
	    current_lineno = 1;
	    yy_scan_string(t);
	    return 0;
	} else
	    return -1;
    }
    fclose(s->file);
    free(current_file);
    yy_delete_buffer(YY_CURRENT_BUFFER);
    if (get_glob() != 0) {
	yy_switch_to_buffer(s->buffer);
	current_lineno = s->lineno;
	current_file = s->filename;
    }
    return 0;
}

/*======================================================================

    The main entry point... returns -1 if the file can't be accessed.

======================================================================*/

int parse_configfile(char *fn)
{
    FILE *f;
    
    f = fopen(fn, "r");
    if (!f) {
	syslog(LOG_ERR, "could not open '%s': %m", fn);
	return -1;
    }
    current_lineno = 1;
    current_file = fn;
    source_stack_ptr = 0;
    yyrestart(f);
    yyparse();
    fclose(f);
    return 0;
}

