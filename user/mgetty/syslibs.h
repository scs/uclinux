#ident "$Id$ Copyright (c) Gert Doering"

/* Include stdlib.h / malloc.h, depending on the O/S
 */

#ifndef _NOSTDLIB_H
#include <stdlib.h>
#endif

#if !defined( __bsdi__ ) && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(NeXT) && !defined(__MACH__)
#include <malloc.h>
#endif

#ifdef NEXTSGTTY		/* NeXT, not POSIX subsystem */
# include <libc.h>
#endif
