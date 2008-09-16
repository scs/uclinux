#include "nxlib.h"

#define FULLCIRCLE (360 * 64)

/* X11 angle1=start, angle2=distance (negative=clockwise)*/
static void
drawArc(Drawable d, GC gc, int x, int y, int width, int height,
	int angle1, int angle2, int mode)
{
	int rx, ry;
	int startAngle, endAngle;

	/* don't draw anything if no arc requested*/
	if (angle2 == 0)
		return;

	/*
	 * Convert X11 width/height to Nano-X radius required
	 * for arc drawing.
	 * This causes problems when width is even, so we
	 * punt for the time being.  This causes smaller
	 * arcs to be drawn than required, but always within
	 * the width/height bounding box.
	 */
	if (!(width & 1))
		--width;
	if (!(height & 1))
		--height;
	rx = width / 2;
	ry = height / 2;

	/*
	 * Convert X11 start/distance angles to Nano-X start/end angles.
	 */
	if (angle1 == 0 && angle2 >= FULLCIRCLE) {
		startAngle = 0;
		endAngle = 0;
	} else {
		if (angle2 > FULLCIRCLE)
			angle2 = FULLCIRCLE;
		else if (angle2 < -FULLCIRCLE)
			angle2 = -FULLCIRCLE;
		if (angle2 < 0) {
			startAngle = angle1 + angle2;
			endAngle = angle1;
		} else {
			startAngle = angle1;
			endAngle = angle1 + angle2;
		}
		if (startAngle < 0)
			startAngle = FULLCIRCLE - (-startAngle) % FULLCIRCLE;
		if (startAngle >= FULLCIRCLE)
			startAngle = startAngle % FULLCIRCLE;
		if (endAngle < 0)
			endAngle = FULLCIRCLE - (-endAngle) % FULLCIRCLE;
		if (endAngle >= FULLCIRCLE)
			endAngle = endAngle % FULLCIRCLE;
	}
	/*printf("drawArc %d,%d %d,%d %d,%d (%d,%d)\n", x, y, width, height, angle1/64, angle2/64, startAngle/64, endAngle/64);*/

	/* Call Nano-X routine, requires floating point*/
	GrArcAngle(d, gc->gid, x+rx, y+ry, rx, ry, startAngle, endAngle, mode);
}

int
XDrawArc(Display *display, Drawable d, GC gc, int x, int y,
	unsigned int width, unsigned int height, int angle1, int angle2)
{
	/* X11 width/height is one less than Nano-X width/height*/
	drawArc(d, gc, x, y, width+1, height+1, angle1, angle2, GR_ARC);
	return 1;
}

int
XDrawArcs(Display *display, Drawable d, GC gc, XArc *arcs, int narcs)
{
	int i;

	for (i = 0; i < narcs; i++) {
		/* X11 width/height is one less than Nano-X width/height*/
		drawArc(d, gc, arcs[i].x, arcs[i].y,
			arcs[i].width+1, arcs[i].height+1, arcs[i].angle1,
			arcs[i].angle2, GR_ARC);
	}
	return 1;
}

int
XFillArc(Display *display, Drawable d, GC gc, int x, int y,
	unsigned int width, unsigned int height, int angle1, int angle2)
{
	drawArc(d, gc, x, y, width, height, angle1, angle2, GR_PIE);
	return 1;
}

int
XFillArcs(Display *display, Drawable d, GC gc, XArc *arcs, int narcs)
{
	int i;

	for (i = 0; i < narcs; i++)
		drawArc(d, gc, arcs[i].x, arcs[i].y, arcs[i].width,
			arcs[i].height, arcs[i].angle1, arcs[i].angle2, GR_PIE);
	return 1;
}
