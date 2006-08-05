/*
 * $Id$
 * ---------------------------------------------------------------------------
 * ARJSFX exported stubs are declared here.
 *
 */

#ifndef ARJSFX_INCLUDED
#define ARJSFX_INCLUDED

/* Prototypes */

#if SFX_LEVEL>=ARJSFXV
char FAR *preprocess_comment(char FAR *comment);
#elif SFX_LEVEL>=ARJSFX
char *preprocess_comment(char *comment);
#endif
void show_sfx_logo();
void sfx_setup();

#endif

