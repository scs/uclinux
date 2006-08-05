/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in EXE_SEAR.C are declared here.
 *
 *
 */

#ifndef EXE_SEAR_INCLUDED
#define EXE_SEAR_INCLUDED

/* Prototypes */

void fetch_sfx();
void fetch_sfxjr();
void fetch_sfxv();
void fetch_sfxstub();

#if SFX_LEVEL<=ARJSFXV
void sfx_seek();
#endif

#endif
