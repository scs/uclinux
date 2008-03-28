#include "nxlib.h"
#include <stdlib.h>
#include <string.h>

char **_nxfontlist = 0;
int _nxfontcount = 0;

FILE *
_nxLoadFontDir(char *str)
{
	char path[256];

	sprintf(path, "%s/fonts.dir", str);
	return fopen(path, "r");
}


void
_nxSetDefaultFontDir(void)
{
	int i;

	if (_nxfontlist) {
		for (i = 0; i < _nxfontcount; i++)
			Xfree(_nxfontlist[i]);
		Xfree(_nxfontlist);
	}

	_nxfontlist = (char **) Xcalloc(2, sizeof(char *));
	_nxfontlist[0] = strdup(X11_FONT_DIR1);
	_nxfontlist[1] = strdup(X11_FONT_DIR2);
	_nxfontcount = 2;
}
