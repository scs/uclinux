#include "nxlib.h"
#include <stdlib.h>
#include <string.h>

/* Parse colors of format:
 * #RGB #RRGGBB #RRRGGGBBB  #RRRRGGGGBBBB
 */
static int
_parseColorStr(_Xconst char **str, int size)
{
	char parse[5];
	unsigned long val;

	strncpy(parse, *str, size);
	parse[size + 1] = '\0';
	val = strtol(parse, 0, 16);
	*str += size;
	return (val);
}

Status
XParseColor(Display * display, Colormap colormap, _Xconst char *spec,
	XColor *exact)
{
	int r, g, b;

	/* This is the new and preferred way */
	if (strncmp(spec, "rgb:", 4) == 0) {
		sscanf(spec + 4, "%x/%x/%x", &r, &g, &b);
	} else {
		if (spec[0] != '#') {
			/* try to parse the color name */
			if (GrGetColorByName((char *) spec, &r, &g, &b) == 0) {
				printf("XParseColor: bad parse on %s\n", spec);
				return 0;
			}
		} else {
			_Xconst char *p = spec + 1;
			unsigned long val;

			switch (strlen(p)) {
			case 3:
				r = _parseColorStr(&p, 1);
				g = _parseColorStr(&p, 1);
				b = _parseColorStr(&p, 1);
				break;

			case 6:
				val = strtol(p, 0, 16);
				r = (val >> 16) & 0xFF;
				g = (val >> 8) & 0xFF;
				b = (val & 0xFF);
				break;

			case 12:	/* #RRRGGGBBB */
				r = _parseColorStr(&p, 3);
				g = _parseColorStr(&p, 3);
				b = _parseColorStr(&p, 3);

				if (r > 0xFF)
					r >>= 4;
				if (g > 0xFF)
					g >>= 4;
				if (b > 0xFF)
					b >>= 4;

				break;

			default:
				printf("XParseColor: invalid size %d on %s\n",
				       strlen(p), p);
				return 0;
			}
		}
	}

	exact->red = r << 8;
	exact->green = g << 8;
	exact->blue = b << 8;
	exact->flags |= (DoRed | DoGreen | DoBlue);

	return 1;
}

Status
XLookupColor(Display * display, Colormap colormap, _Xconst char *spec,
	     XColor * exact, XColor * screen)
{
	Status stat = XParseColor(display, colormap, spec, exact);

	if (!stat)
		return stat;

	/* FIXME:  Should do a system look up for the right color */
	/* This will come back and haunt you on palettized machines */

	screen->red = exact->red;
	screen->green = exact->green;
	screen->blue = exact->blue;

	screen->flags |= (DoRed | DoGreen | DoBlue);

	return stat;
}
