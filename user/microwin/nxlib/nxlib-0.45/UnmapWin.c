#include "nxlib.h"

int
XUnmapWindow (Display *dpy, Window w)
{
	printf("Unmapping window %d\n", w);
	GrUnmapWindow(w);
	return 1;
}

Status
XWithdrawWindow(Display * display, Window w, int screen_number)
{
	printf("Withdrawing window %d\n", w);
	GrUnmapWindow(w);
	return 1;
}
