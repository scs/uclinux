#include "nxlib.h"

static void
drawArc(Drawable d, GC gc, int x, int y, int width, int height,
	int angle1, int angle2, int mode)
{
	int rx = width / 2;
	int ry = height / 2;

	/* Note that this requires floating point.  Not good */
	GrArcAngle(d, gc->gid, x + rx, y + ry, rx, ry, angle1, angle2, mode);
}

int
XDrawArc(Display * display, Drawable d, GC gc, int x, int y,
	unsigned int width, unsigned int height, int angle1, int angle2)
{
	drawArc(d, gc, x, y, width, height, angle1, angle2, GR_ARC);
	return 1;
}

int
XDrawArcs(Display * display, Drawable d, GC gc, XArc * arcs, int narcs)
{
	int i;

	for (i = 0; i < narcs; i++)
		drawArc(d, gc, arcs[i].x, arcs[i].y,
			     arcs[i].width, arcs[i].height, arcs[i].angle1,
			     arcs[i].angle2, GR_ARC);
	return 1;
}

int
XFillArc(Display * display, Drawable d, GC gc, int x, int y,
	unsigned int width, unsigned int height, int angle1, int angle2)
{
	drawArc(d, gc, x, y, width, height, angle1, angle2, GR_PIE);
	return 1;
}

int
XFillArcs(Display * display, Drawable d, GC gc, XArc * arcs, int narcs)
{
	int i;

	for (i = 0; i < narcs; i++)
		drawArc(d, gc, arcs[i].x, arcs[i].y, arcs[i].width,
			arcs[i].height, arcs[i].angle1, arcs[i].angle2, GR_PIE);
	return 1;
}
