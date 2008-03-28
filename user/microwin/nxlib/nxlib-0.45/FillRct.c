#include "nxlib.h"
#include <stdio.h>

int
XFillRectangle(Display *xdpy, Drawable d, GC gc, int x, int y,
	unsigned int width, unsigned int height)
{
  
	GrFillRect(d, gc->gid, x, y, width, height);
	return 1;
}

int 
XFillRectangles(Display *dpy, Drawable d, GC gc, XRectangle *rects, int nrects) {
	int i;

	for(i = 0; i < nrects; i++) 
		XFillRectangle(dpy, d, gc, rects[i].x, rects[i].y,
				rects[i].width, rects[i].height);

	return 1;
}
