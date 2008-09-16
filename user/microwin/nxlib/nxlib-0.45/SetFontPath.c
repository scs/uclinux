#include "nxlib.h"
#include <string.h>
#include "Xatom.h"

char **
_nxGetFontDir(int *count)
{
	int i;

	int size;
	char **ret;

	if (!_nxfontcount)
		_nxSetDefaultFontDir();

	size = _nxfontcount + 1;
	ret = (char **) Xcalloc(size, sizeof(char *));

	for (i = 0; i < _nxfontcount; i++)
		ret[i] = strdup(_nxfontlist[i]);
	ret[_nxfontcount] = 0;

	*count = _nxfontcount;
	return (ret);
}

void
_nxSetFontDir(char **directories, int ndirs)
{
	int i;

	if (_nxfontlist) {
		for (i = 0; i < _nxfontcount; i++)
			Xfree(_nxfontlist[i]);
		Xfree(_nxfontlist);
	}

	_nxfontlist = (char **) Xcalloc(ndirs, sizeof(char *));
	for (i = 0; i < ndirs; i++)
		_nxfontlist[i] = strdup(directories[i]);

	_nxfontcount = ndirs;
}

void
_nxFreeFontDir(char **list)
{
	int i;

	if (list) {
		for (i = 0; list[i]; i++)
			Xfree(list[i]);
		Xfree(list);
	}
}

int
XSetFontPath(Display * display, char **directories, int ndirs)
{
	_nxSetFontDir(directories, ndirs);
	return 1;
}

char **
XGetFontPath(Display * display, int *npaths_return)
{
	return _nxGetFontDir(npaths_return);
}

int
XFreeFontPath(char **list)
{
	_nxFreeFontDir(list);
	return 1;
}

Bool
XGetFontProperty(XFontStruct * font, Atom atom, unsigned long *value_return)
{
printf("XGetFontProperty called\n");
	switch (atom) {
	case XA_FONT:			/* 18*/
	case XA_UNDERLINE_POSITION:	/* 51*/
	case XA_UNDERLINE_THICKNESS:	/* 52*/
		break;
	default:
		printf("XGetFontProperty: Unknown FontProperty Atom %d\n",
			(int)atom);
	}
	return 0;
}
