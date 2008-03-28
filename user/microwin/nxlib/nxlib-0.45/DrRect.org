#include "nxlib.h"

int
XDrawRectangle(Display * display, Drawable d, GC gc, int x, int y,
	       unsigned int width, unsigned int height)
{
	GrRect(d, gc->gid, x, y, width, height);
	return 1;
}

int
XDrawRectangles(Display * display, Drawable d, GC gc, XRectangle * rect,
		int nrect)
{

	int i;

	for (i = 0; i < nrect; i++)
		GrRect(d, gc->gid, rect[i].x, rect[i].y, rect[i].width,
		       rect[i].height);

	return 1;
}
