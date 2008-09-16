#include "nxlib.h"

int
XFreeGC(Display *dpy, GC gc)
{
	GrDestroyGC(gc->gid);

	Xfree((XGCValues *)gc->ext_data);
	Xfree(gc);
	return 1;
}
