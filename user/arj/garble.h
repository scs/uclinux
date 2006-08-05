/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in GARBLE.C are declared here.
 *
 */

#ifndef GARBLE_INCLUDED
#define GARBLE_INCLUDED

/* Prototypes */

int garble_init(char modifier);
void garble_encode(char *data, int len);
void garble_decode(char *data, int len);

#endif

