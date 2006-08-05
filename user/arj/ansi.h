/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ANSI.C are declared here.
 *
 */

#ifndef ANSI_INCLUDED
#define ANSI_INCLUDED

/* Standard ANSI sequence identifiers */

#define ANSI_ESC                  27    /* Escape character */
#define ANSI_BRACKET             '['    /* Used to identify ANSI sequences */
#define ANSI_DELIMITER           ';'    /* Parameter list delimiter */

/* Prototypes */

#if TARGET==OS2
 #define display_ansi(c) putchar(c)
#else
 void display_ansi(char c);
#endif

#endif

