//
// "$Id: N_X.H,v 1.00 2000/05/25 16:25:45 Tang hao "
//
// Nano-X header file for the Fast Light Tool Kit (FLTK).
//
// Copyright 2000-2000 by Tang Hao.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA.
//
// Please report all bugs and problems to "fltk-bugs@easysw.com".
//

// Do not directly include this file, instead use <FL/x.H>.  It will
// include this file if NANO_X is defined.  This is to encourage
// portability of even the system-specific code...

#define MWINCLUDECOLORS
#include <nano-X.h>

//#if defined(_ABIN32) || defined(_ABI64) // fix for broken SGI Irix X .h files
//#pragma set woff 3322
//#endif
//#include <X11/Xlib.h>
//#include <X11/Xutil.h>
//#if defined(_ABIN32) || defined(_ABI64)
//#pragma reset woff 3322
//#endif
//#include <X11/Xatom.h>
#include "Fl_Window.H"

//tanghao
#define Window GR_WINDOW_ID 
#define GC GR_GC_ID
#define XVisualInfo int
#define Colormap int
#define Region int
/*typedef struct
{
int x;
int y;
}Cursor;
*/
#define Cursor int
//tanghao
#define None 0
FL_EXPORT void fl_open_display();
FL_EXPORT void fl_close_display();

// constant info about the X server connection:
//extern FL_EXPORT Display *fl_display;
extern FL_EXPORT int fl_display;
extern FL_EXPORT int fl_screen;
extern FL_EXPORT XVisualInfo *fl_visual;
extern FL_EXPORT Colormap fl_colormap;

// drawing functions:
//extern FL_EXPORT GC fl_gc;
extern FL_EXPORT GR_GC_ID fl_gc;
//extern FL_EXPORT Window fl_window;
extern FL_EXPORT GR_WINDOW_ID fl_window;
//extern FL_EXPORT XFontStruct* fl_xfont;
extern FL_EXPORT GR_FONT_ID fl_xfont;

FL_EXPORT ulong fl_xpixel(Fl_Color i);
FL_EXPORT ulong fl_xpixel(uchar r, uchar g, uchar b);
FL_EXPORT void fl_clip_region(Region);
FL_EXPORT Region XRectangleRegion(int x, int y, int w, int h); // in fl_rect.cxx

// feed events into fltk:
//FL_EXPORT int fl_handle(const XEvent&);
FL_EXPORT int fl_handle(const GR_EVENT&);

// you can use these in Fl::add_handler() to look at events:
//extern FL_EXPORT const XEvent* fl_xevent;
//extern FL_EXPORT const GR_EVENT fl_xevent;
extern FL_EXPORT GR_EVENT * fl_xevent;
extern FL_EXPORT ulong fl_event_time;

// off-screen pixmaps: create, destroy, draw into, copy to window:
#define Fl_Offscreen GR_WINDOW_ID
#define fl_create_offscreen(w,h) GrNewPixmap(w,h,0)
//
//  XCreatePixmap(fl_display, fl_window, w, h, fl_visual->depth)
// begin/end are macros that save the old state in local variables:
#define fl_begin_offscreen(pixmap) \
  Window _sw=fl_window; fl_window=pixmap; fl_push_no_clip()
#define fl_end_offscreen() \
  fl_pop_clip(); fl_window=_sw

#define fl_copy_offscreen(x,y,w,h,pixmap,srcx,srcy) \
        GrCopyArea(fl_window,fl_gc,x,y,w,h,pixmap,srcx,srcy,MWROP_SRCCOPY)
			//(GR_DRAW_ID id, GR_GC_ID gc, GR_COORD x, GR_COORD y,
			//GR_SIZE width, GR_SIZE height, GR_DRAW_ID srcid,
			//GR_COORD srcx, GR_COORD srcy, int op);
//
//  XCopyArea(fl_display, pixmap, fl_window, fl_gc, srcx, srcy, w, h, x, y)
#define fl_delete_offscreen(pixmap) GrDestroyWindow(pixmap)
//XFreePixmap(fl_display, pixmap)

// this object contains all X-specific stuff about a window:
// Warning: this object is highly subject to change!  It's definition
// is only here so that fl_xid can be declared inline:

class Fl_X {

public:
  static int mw_parent;
  static int mw_parent_xid;
  static int mw_parent_top;
  static int fix_exposure;
  Window xid;
  Window other_xid;
  Fl_Window *w;
  Region region;
  Fl_X *next;
  char wait_for_expose;
  char backbuffer_bad; // used for XDBE
  static FL_EXPORT Fl_X* first;
  static FL_EXPORT Fl_X* i(const Fl_Window* w) {return w->i;}
  FL_EXPORT void setwindow(Fl_Window* wi) {w=wi; wi->i=this;}
  FL_EXPORT void sendxjunk();
  static FL_EXPORT void make_xid(Fl_Window*,XVisualInfo* =fl_visual, Colormap=fl_colormap);
  static FL_EXPORT Fl_X* set_xid(Fl_Window*, Window);
  // kludges to get around protection:
  FL_EXPORT void flush() {w->flush();}
  static FL_EXPORT void x(Fl_Window* w, int X) {w->x(X);}
  static FL_EXPORT void y(Fl_Window* w, int Y) {w->y(Y);}
};

// convert xid <-> Fl_Window:
inline Window fl_xid(const Fl_Window*w) {return Fl_X::i(w)->xid;}
FL_EXPORT Fl_Window* fl_find(Window xid);

extern FL_EXPORT char fl_override_redirect; // hack into Fl_X::make_xid()
extern FL_EXPORT int fl_background_pixel;  // hack into Fl_X::make_xid()

//
// End of "$Id: N_X.H,v 1.00 2000/05/25 16:25:45 Tang hao "
//
