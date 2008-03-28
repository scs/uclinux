#include <string.h>
#include "nxlib.h"

int
XGetWindowProperty(Display * dpy, Window win, Atom prop, long offset,
	long len, Bool bDel, Atom req, Atom * type, int *format,
	unsigned long *nitems, unsigned long *bytes, unsigned char **data)
{
	*type = None;
	*format = 0;
	*data = 0;
	*nitems = 0;
	*bytes = 0;
	return 1;		/* failure */
}

Status
XGetWindowAttributes(Display * display, Window w, XWindowAttributes * ret)
{
	GR_WINDOW_INFO info;

	memset(ret, 0, sizeof(*ret));

	GrGetWindowInfo(w, &info);
	ret->x = info.x;
	ret->y = info.y;
	ret->width = info.width;
	ret->height = info.height;
	ret->border_width = info.bordersize;
	ret->depth = XDefaultDepth(display, 0);
	ret->visual = XDefaultVisual(display, 0);
	ret->class = ret->visual->class;
	ret->root = GR_ROOT_WINDOW_ID;
	ret->colormap = XDefaultColormap(display, 0);
	if (info.mapped)
		ret->map_state = info.realized? IsViewable: IsUnviewable;
	else ret->map_state = IsUnmapped;
	//FIXME ret->override_redirect = (info.props & GR_WM_PROPS_NODECORATE) != 0;
	ret->screen = &display->screens[0];
	return 1;
}
