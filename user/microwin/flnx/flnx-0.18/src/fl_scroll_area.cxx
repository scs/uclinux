//
// "$Id: fl_scroll_area.cxx,v 1.1.1.1 2003/08/07 21:18:41 jasonk Exp $"
//
// Scrolling routines for the Fast Light Tool Kit (FLTK).
//
// Copyright 1998-1999 by Bill Spitzak and others.
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

// Drawing function to move the contents of a rectangle.  This is passed
// a "callback" which is called to draw rectangular areas that are moved
// into the drawing area.

#include <FL/x.H>

// scroll a rectangle and redraw the newly exposed portions:
void fl_scroll(int X, int Y, int W, int H, int dx, int dy,
	       void (*draw_area)(void*, int,int,int,int), void* data)
{
  if (!dx && !dy) return;
  if (dx <= -W || dx >= W || dy <= -H || dy >= H) {
    // no intersection of old an new scroll
    draw_area(data,X,Y,W,H);
    return;
  }
  int src_x, src_w, dest_x, clip_x, clip_w;
  if (dx > 0) {
    src_x = X;
    dest_x = X+dx;
    src_w = W-dx;
    clip_x = X;
    clip_w = dx;
  } else {
    src_x = X-dx;
    dest_x = X;
    src_w = W+dx;
    clip_x = X+src_w;
    clip_w = W-src_w;
  }
  int src_y, src_h, dest_y, clip_y, clip_h;
  if (dy > 0) {
    src_y = Y;
    dest_y = Y+dy;
    src_h = H-dy;
    clip_y = Y;
    clip_h = dy;
  } else {
    src_y = Y-dy;
    dest_y = Y;
    src_h = H+dy;
    clip_y = Y+src_h;
    clip_h = H-src_h;
  }
#ifdef WIN32
  BitBlt(fl_gc, dest_x, dest_y, src_w, src_h, fl_gc, src_x, src_y,SRCCOPY);
  // NYI: need to redraw areas that the source of BitBlt was bad due to
  // overlapped windows, probably similar to X version:
#else
#ifdef NANO_X //tanghao
  GrCopyArea(fl_window,fl_gc,dest_x,dest_y,src_w,src_h,fl_window,src_x,src_y,MWROP_SRCCOPY);
#else
  XCopyArea(fl_display, fl_window, fl_window, fl_gc,
	    src_x, src_y, src_w, src_h, dest_x, dest_y);
#endif //tanghao
  // we have to sync the display and get the GraphicsExpose events! (sigh)
  for (;;) {
#ifdef NANO_X // Century Software
    draw_area(data, dest_x, dest_y, src_w, src_h);
    break;
#else
    XEvent e; XWindowEvent(fl_display, fl_window, ExposureMask, &e);
    if (e.type == NoExpose) break;
    // otherwise assumme it is a GraphicsExpose event:
    draw_area(data, e.xexpose.x, e.xexpose.y,
	      e.xexpose.width, e.xexpose.height);
    if (!e.xgraphicsexpose.count) break;
#endif //tanghao
  }
#endif
  if (dx) draw_area(data, clip_x, dest_y, clip_w, src_h);
  if (dy) draw_area(data, X, clip_y, W, clip_h);
}

//
// End of "$Id: fl_scroll_area.cxx,v 1.1.1.1 2003/08/07 21:18:41 jasonk Exp $".
//
