/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ENCODE.C are declared here.
 *
 */

#ifndef ENCODE_INCLUDED
#define ENCODE_INCLUDED

/* Prototypes */

void encode(int method);
void encode_f();

/* Forwarded from this module or ENC_ASM.ASM */

void putbits(int n, unsigned short x);

#endif

