#include "nxlib.h"
#include "Xutil.h"

XClassHint *
XAllocClassHint(void)
{
	return (XClassHint *) Xcalloc(1, sizeof(XClassHint));
}

