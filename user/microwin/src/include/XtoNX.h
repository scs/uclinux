#ifndef __XTONX_H
#define __XTONX_H
/*
 * Copyright (c) 2001 by Greg Haerr <greg@centurysoftware.com>
 *
 * XtoNX.h - X to Nano-X macro conversion header file
 *
 * Yes, this is a vain attempt at making things easier when
 * porting Xlib programs to Nano-X!
 */

extern "C" {

#define MWINCLUDECOLORS
#include "nano-X.h"

typedef struct _display		Display;
typedef GR_WINDOW_ID		Window;
typedef GR_WINDOW_ID		Pixmap;
typedef GR_GC_ID		GC;
typedef GR_FONT_ID		Font;
typedef MWCURSOR		Cursor;
typedef unsigned long		Time;		/* change to GR_TIME*/
typedef GR_EVENT		XEvent;
typedef GR_FONT_INFO		XFontStruct;
typedef GR_POINT		XPoint;

// kluge structs
#define XCharStruct		char

#define RootWindow(d,s)		GR_ROOT_WINDOW_ID
#define DefaultScreen(d)	0
#define DefaultDepth(d,s)	16
#define BlackPixel(d,s)		BLACK
#define WhitePixel(d,s)		WHITE
#define False			0
#define True			1

// events
#define EnterWindowMask		GR_EVENT_MASK_MOUSE_ENTER
#define LeaveWindowMask		GR_EVENT_MASK_MOUSE_EXIT
#define ButtonPressMask		GR_EVENT_MASK_BUTTON_DOWN
#define ButtonReleaseMask	GR_EVENT_MASK_BUTTON_UP
#define KeyPressMask		GR_EVENT_MASK_KEY_DOWN
#define KeyReleaseMask		GR_EVENT_MASK_KEY_UP
#define ExposureMask		GR_EVENT_MASK_EXPOSURE

#define EnterNotify		GR_EVENT_TYPE_MOUSE_ENTER
#define LeaveNotify		GR_EVENT_TYPE_MOUSE_EXIT
#define ButtonPress		GR_EVENT_TYPE_BUTTON_DOWN
#define ButtonRelease		GR_EVENT_TYPE_BUTTON_UP
#define KeyPress		GR_EVENT_TYPE_KEY_DOWN
#define KeyRelease		GR_EVENT_TYPE_KEY_UP
#define Expose			GR_EVENT_TYPE_EXPOSURE

#define XNextEvent(d,ep)			GrGetNextEvent(ep)
#define XSelectInput(d,w,m)			GrSelectEvents(w,m)
#define XFlush(d)				GrFlush()
#define XSync(d,f)				GrFlush()

// graphics functions
#define XCreateSimpleWindow(d,p,x,y,w,h,bw,bordc,backc) \
			GrNewWindow(p,x,y,w,h,bw,backc,bordc)
#define XCreatePixmapFromBitmapData(d,w,bm,W,H,f,b,depth) \
			GrNewPixmapFromData(W,H,f,b,(void *)bm, \
				GR_BMDATA_BYTEREVERSE|GR_BMDATA_BYTESWAP)
#define XDestroyWindow(d,w)			GrDestroyWindow(w)
#define XReparentWindow(d,w,p,x,y) /* FIXME GrReparentWindow(w,p,x,y)*/
#define XMapWindow(d,w)				GrMapWindow(w)
#define XUnmapWindow(d,w)			GrUnmapWindow(w)
#define XClearWindow(d,w)			GrClearWindow(w,0)
#define XRaiseWindow(d,w)			GrRaiseWindow(w)
#define XLowerWindow(d,w)			GrLowerWindow(w)
#define XMoveWindow(d,w,x,y)			GrMoveWindow(w,x,y)
#define XResizeWindow(d,w,W,H)			GrResizeWindow(w,W,H)

#define XCreateGC(d,a,b,c)			GrNewGC()
#define XSetFunction(d,g,f)			GrSetGCMode(g,f)
#define GXxor		GR_MODE_XOR
#define XSetForeground(d,g,c)			GrSetGCForeground(g,c)
#define XSetWindowBackgroundPixmap(d,w,p) \
			GrSetBackgroundPixmap(w,p,GR_BACKGROUND_TILE)
#define XSetWindowBackground(d,w,c)		GrSetWindowBackgroundColor(w,c)
#define XSetWindowBorderWidth(d,w,bw)		GrSetWindowBorderSize(w,bw)
#define XSetWindowBorder(d,w,c)			GrSetWindowBorderColor(w,c)
#define XStoreName(d,w,n) 			GrSetWindowTitle(w,n)
#define XSetIconName(d,w,n)	/* nyi*/
#define XDrawLines(d,w,g,ar,cnt,B)		GrDrawLines(w,g,ar,cnt)
#define XFillRectangle(d,w,g,x,y,W,H)		GrFillRect(w,g,x,y,W,H)
#define XDrawString(d,w,g,x,y,s,c)	GrText(w,g,x,y,(void *)s,c,GR_TFASCII)
#define XSetFont(d,g,f)				GrSetGCFont(g,f)
#define XLoadFont(d,f)				GrCreateFont(0, 0, 0)
#define XDefineCursor(d,w,c)	/* nyi*/
#define XUndefineCursor(d,w)	/* nyi*/

} // extern "C"

#endif /* __XTONX_H*/
