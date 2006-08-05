/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in GOST40.C are declared here.
 *
 *
 */

#ifndef GOST40_INCLUDED
#define GOST40_INCLUDED

/* Prototypes */

void gost40_init(unsigned char modifier);
void gost40_encode_stub(char *data, int len);
void gost40_decode_stub(char *data, int len);

#endif

