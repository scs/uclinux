/*----------------------------------------------------------------------------
 * (C) 1997-2001 Armin Biere 
 *
 *     $Id$
 *----------------------------------------------------------------------------
 */

#ifndef _ccmalloc_h_INCLUDED
#define _ccmalloc_h_INCLUDED

#include <sys/types.h>

void *ccmalloc_malloc (size_t);
void ccmalloc_free (void *);
void ccmalloc_report (void);
void ccmalloc_static_initialization(void);
void ccmalloc_atexit(void(*)(void));
void ccmalloc_abort (const char * fmt, ...);

#endif
