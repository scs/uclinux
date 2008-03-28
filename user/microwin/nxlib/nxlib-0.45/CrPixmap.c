#include "nxlib.h"

Pixmap
XCreatePixmap(Display * dpy, Drawable d, unsigned int width,
	unsigned int height, unsigned int depth)
{
	/* Drawable ignored with nano-X */
printf("XCreatePixmap %d,%d depth %d\n", width, height, depth);
	// FIXME depth ignored in pixmap
	if (depth == 1) printf("XCreatePixmap created with depth 1\n");
	return GrNewPixmap(width, height, NULL);
}

int
XFreePixmap(Display * display, Pixmap pixmap)
{

	GrDestroyWindow(pixmap);
	return 1;
}
