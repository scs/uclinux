#ifndef _NXLIB_H_
#define _NXLIB_H_

/* Changeable options*/
#define USE_ALLOCA		1	/* set if system has alloca()*/
#define MALLOC_0_RETURNS_NULL	0	/* not yet needed*/

/* required settings*/
#define NeedFunctionPrototypes	1	/* ANSI C*/
#define XLIB_ILLEGAL_ACCESS	1	/* define real structures*/

/* deal with _Xconst differences in X11 header files*/
#ifndef XCONST
#define XCONST	_Xconst
#endif

/*
 * bet you never thought you'd see both of these in the same file ;-)
 */
#include "Xlib.h"
#include <nano-X.h>

#include <stdio.h>
#include <malloc.h>

/* malloc stuff*/
#if MALLOC_0_RETURNS_NULL
/* for machines that do not return a valid pointer for malloc(0)*/
# define Xmalloc(size) malloc(((size) == 0 ? 1 : (size)))
# define Xrealloc(ptr, size) realloc((ptr), ((size) == 0 ? 1 : (size)))
# define Xcalloc(nelem, elsize) calloc(((nelem) == 0 ? 1 : (nelem)), (elsize))
#else
# define Xmalloc(size) malloc((size))
# define Xrealloc(ptr, size) realloc((ptr), (size))
# define Xcalloc(nelem, elsize) calloc((nelem), (elsize))
#endif
#define Xfree(ptr) free((ptr))

#if USE_ALLOCA
/* alloca() is available, so use it for better performance */
#define ALLOCA(size)	alloca(size)
#define FREEA(pmem)
#else
/* no alloca(), so use malloc()/free() instead */
#define ALLOCA(size)	Xmalloc(size)
#define FREEA(pmem)	Xfree(pmem)
#endif

/* defines for unmodified (Xrm) Xlib routines...*/
//#define bzero(mem, size)	memset(mem, 0, size)
#define LockDisplay(dpy)
#define UnlockDisplay(dpy)
#define _XLockMutex(lock)
#define _XUnlockMutex(lock)
#define _XCreateMutex(lock)
#define _XFreeMutex(lock)

/* Used internally for the colormap */
typedef struct  {
	GR_PIXELVAL	value;
	int		ref;
} nxColorval;

typedef struct _nxColormap {
	int			id;
	int			color_alloc;
	int			cur_color;
	nxColorval *		colorval;
	struct _nxColormap *	next;
} nxColormap;

/* Colormap.c */
nxColormap *_nxFindColormap(Colormap id);
Colormap _nxDefaultColormap(Display *dpy);

/* Colorname.c*/
GR_COLOR GrGetColorByName(char *colorname, int *retr, int *retg, int *retb);

/* AllocColor.c*/
void _nxPixel2RGB(Display * display, unsigned long color,
	   unsigned short *red, unsigned short *green, unsigned short *blue);

/* QueryColor.c*/
GR_COLOR _nxColorvalFromPixelval(Display *dpy, unsigned long pixelval);

/* font.c */
extern char **_nxfontlist;
extern int _nxfontcount;
FILE * _nxLoadFontDir(char *str);
void _nxSetDefaultFontDir(void);

/* SetFontPath.c*/
void _nxSetFontDir(char **directories, int ndirs);
char** _nxGetFontDir(int *count);
void _nxFreeFontDir(char **list);

/* LoadFont.c*/
char *_nxFindX11Font(const char *in_font);

/* ChProperty.c */
int _nxDelAllProperty(Window w);

/* SelInput.c*/
GR_EVENT_MASK _nxTranslateEventMask(unsigned long mask);

/* CrCursor.c*/
GR_CURSOR_ID _nxCreateCursor(GR_WINDOW_ID cursor, GR_RECT * cbb,
	GR_WINDOW_ID mask, GR_RECT * mbb, int hotx, int hoty,
	GR_COLOR fg, GR_COLOR bg);

/* OpenDisp.c*/
void _XFreeDisplayStructure(Display *dpy);
extern Font _nxCursorFont;

/* CrGC.c*/
int _nxConvertROP(int Xrop);

#endif /* _NXLIB_H_*/
