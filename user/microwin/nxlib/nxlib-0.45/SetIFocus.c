#include "nxlib.h"

int
XSetInputFocus(Display *dpy, Window focus, int revert_to, Time time)
{
printf("SetInputFocus %d\n", focus);
	GrSetFocus(focus);
	return 1;
}
