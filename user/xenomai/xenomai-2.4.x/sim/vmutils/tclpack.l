%{
/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@idealx.com>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
 * The original code is CarbonKernel - Real-time Operating System Simulator,
 * released April 15, 2000. The initial developer of the original code is
 * Realiant Systems (http://www.realiant.com).
 *
 * Description: An obfuscated Tcl-code packer.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#include <ctype.h>
#include <stdio.h>

#define MAX_CHARS_PER_LINE 64

static int eating_comment,
           current_column,
           next_file,
           all_files;

static char **file_array;

static YY_BUFFER_STATE this_flexbuf;

static FILE *this_fp;

void output_char(int c),
     output_string(const char *s);
%}

%%

\\$           {  if (eating_comment) eating_comment++;
                 else REJECT; }

^\n             if (eating_comment) --eating_comment;

\n              { if (eating_comment) --eating_comment;
                  else output_char('\n'); }

\\.             if (!eating_comment) output_string(yytext);

^[\t ]*#.*      {
                eating_comment = 1;

		if (yyleng > 1 &&
		    yytext[yyleng - 1] == '\\' &&
		    yytext[yyleng - 2] != '\\')
		    eating_comment++;
                }

\"[^"]*\"	{
		if (yytext[yyleng - 2] == '\\' && yytext[yyleng - 3] != '\\')
                    {
                    yyless(yyleng - 1);
		    yymore();
                    }
                else
                    output_string(yytext);
		}

[\t ]+          output_char(' ');

.               output_char(*yytext);

%%

static inline void do_output_char (int c)

{
    if (++current_column > MAX_CHARS_PER_LINE)
        {
        fputs("\\\n",stdout);
        current_column = 0;
        }

    switch (c) {
        case '\n': fputs("\\n",stdout); break;
        case '\\': fputs("\\\\",stdout); break;
        case '"': fputs("\\\"",stdout); break;
        default: fputc(c,stdout);
    }
}

void output_char (int c)

{ if (!eating_comment) do_output_char(c); }

void output_string (const char *s)

{ if (!eating_comment) while (*s) do_output_char(*s++); }

int yywrap ()

{
    if (this_fp)
	{
	(void)fclose(this_fp);
	yy_delete_buffer(this_flexbuf);

	/* This is important to have a newline character inserted
	   at the end of every packed script to prevent syntax errors
	   to be detected by Tcl as a result of packing files which do
	   not end with such character. For example, a close-brace
	   ending the first file will be separated from a non-space
	   character starting the second file, and not left immediately
	   adjacent to it. This is the reason why tclpack must know
	   how to read its input files from the command line in order
	   to find when a file transition occurs. */

 	output_char('\n');
	}

    if (next_file >= all_files)
	return 1; /* done */

    this_fp = fopen(file_array[next_file],"r");

    if (!this_fp)
	{
	fprintf(stderr,"tclpack: cannot open %s for reading\n",
                file_array[next_file]);
        return 1;
	}

    next_file++;
    this_flexbuf = yy_create_buffer(this_fp,16384);
    yy_switch_to_buffer(this_flexbuf);

    return 0;
}

int main (int argc, char *argv[])

{
     int xcode;

     next_file = 0;
     all_files = argc - 1;
     file_array = &argv[1];
     (void)yywrap();

     fputs("\"!",stdout);
     xcode = yylex();
     fputs("\",\n",stdout);

     return xcode;
}
