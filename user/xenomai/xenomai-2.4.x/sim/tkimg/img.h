/* img.h */

#ifndef _IMG
#define _IMG

#include "tcl.h"
#include "tk.h"

#define IMG_MAJOR_VERSION 1
#define IMG_MINOR_VERSION 0
#define IMG_PATCH_LEVEL "1.0"

#ifndef RESOURCE_INCLUDED

#if defined(__WIN32__)
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
#   undef WIN32_LEAN_AND_MEAN
#   if defined(_MSC_VER)
#	define EXPORT(a,b) __declspec(dllexport) a b
#   else
#	if defined(__BORLANDC__)
#	    define EXPORT(a,b) a _export b
#	else
#	    define EXPORT(a,b) a b
#	endif
#   endif
#else
#   define EXPORT(a,b) a b
#endif

EXTERN EXPORT(int,Img_Init) _ANSI_ARGS_((Tcl_Interp *interp));
EXTERN EXPORT(int,Img_SafeInit) _ANSI_ARGS_((Tcl_Interp *interp));

#endif /* RESOURCE_INCLUDED */

#endif /* _IMG */
