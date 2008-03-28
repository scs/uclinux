#include "nxlib.h"
#include <stdlib.h>
#include <string.h>

static int
prefix(const char *prestr, char *allstr)
{
	while (*prestr)
		if (*prestr++ != *allstr++)
			return 0;
	if (*allstr != '.')
		return 0;
	return 1;
}

char *
_nxFindX11Font(const char *xfontname)
{
	int fcount, i, f;
	char *ret;
	char buffer[128];

	if (!_nxfontcount)
		_nxSetDefaultFontDir();

	/* Go through all of the font dirs */
	for (f = 0; f < _nxfontcount; f++) {
		FILE *fontdir = _nxLoadFontDir(_nxfontlist[f]);
		if (!fontdir)
			continue;

		fgets(buffer, 128, fontdir);
		fcount = atoi(buffer);

		if (!fcount) {
			fclose(fontdir);
			continue;
		}

		for (i = 0; i < fcount; i++) {
			char *file = buffer, *font = 0;

			fgets(buffer, 128, fontdir);

			/* Remove the end 'o line */
			buffer[strlen(buffer) - 1] = '\0';

			/* Find the field seperator */

			font = strchr(buffer, ' ');
			*font++ = '\0';

			//printf("checking '%s' '%s'\n", xfontname, font);
			if (strcmp(xfontname, font) == 0) {
				ret = (char *) Xmalloc(strlen(_nxfontlist[f]) +
						      strlen(file) + 2);
				sprintf(ret, "%s/%s", _nxfontlist[f], file);

				fclose(fontdir);
				return ret;
			}
		}

		/* not found, try <prefix.pcf> */
		fseek(fontdir, 0L, SEEK_SET);
		fgets(buffer, 128, fontdir);
		for (i = 0; i < fcount; i++) {
			char *file = buffer, *font = 0;

			fgets(buffer, 128, fontdir);

			/* Remove the end 'o line */
			buffer[strlen(buffer) - 1] = '\0';

			/* Find the field seperator */

			font = strchr(buffer, ' ');
			*font++ = '\0';

			//printf("chk2 '%s' '%s'\n", xfontname, file);
			if (prefix(xfontname, file)) {
				ret = (char *) Xmalloc(strlen(_nxfontlist[f]) +
						      strlen(file) + 2);
				sprintf(ret, "%s/%s", _nxfontlist[f], file);

				fclose(fontdir);
				return ret;
			}
		}

		if (fontdir)
			fclose(fontdir);
	}
	return 0;
}

static int
any(int c, const char *str)
{
	while (*str)
		if (*str++ == c)
			return 1;
	return 0;
}

Font
XLoadFont(Display * dpy, _Xconst char *name)
{
	GR_FONT_ID font = 0;
	char *fontname;

	/* first check for wildcards*/
	if (any('*', name) || any('?', name)) {
		char **fontlist;
		int count;

		/* pick first sorted return value for now...*/
		fontlist = XListFonts(dpy, name, 100000, &count);
		if (fontlist)
			fontname = fontlist[0];
	} else
		fontname = (char *)name;

	/* first try to find from X11/fonts.dir file*/
	fontname = _nxFindX11Font(fontname);

	/* if not found, try 6x13 for "fixed"*/
	if (!fontname && !strcmp(name, "fixed"))
		fontname = _nxFindX11Font("6x13");

	/* found font, load into server*/
	if (fontname)
		font = GrCreateFont(fontname, 0, NULL);

printf("XLoadFont('%s') = '%s' [%d]\n", name, fontname, font);
	if (fontname)
		Xfree(fontname);
	return font;
}

/* Stub out XCreateFontSet - but return the right values so we don't 
   freak out GTK 
*/
XFontSet
XCreateFontSet(Display *display, _Xconst char *base_font_name_list, 
	char ***missing_charset_list_return, int *missing_charset_count_return,
	char **def_string_return)
{
	*missing_charset_list_return = NULL;
	*missing_charset_count_return = 0;
	return NULL;
}
