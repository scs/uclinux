/* views - view images exclusive with SDM
* Copyright (C) cappa <cappa@referee.at>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "include/views.h"

void author(void)
{
        fprintf(stderr, "Originally written by cappa <cappa@referee.at>\n");
}

void help(void)
{
        fprintf(stderr, "Help for %s:\n", PACKAGE);
	fprintf(stderr, "%s [OPTIONS] [image|directory]\n\n", PACKAGE);
#ifdef HAVE_WGET
        fprintf(stderr, "\t-u, --url\topens (supported format) file after successful fetch with wget\n");
#endif
	fprintf(stderr, "\t-f, --fs\tstarts views in fullscreen\n");
	fprintf(stderr, "\t-l, --longhelp\tprints long help for views\n");
        fprintf(stderr, "\t-v, --version \tprints version info\n");
        fprintf(stderr, "\t-h, --help \tprints this\n\n");
        author();
        death();
}

void longhelp(void)
{
	
	fprintf(stderr, "Functions in program:\n");
	fprintf(stderr, "ESC\t\t-> quits views and returns to shell\n");
	fprintf(stderr, "F\t\t-> turns fullscreen on\n");
	fprintf(stderr, "N\t\t-> returns to normal window screen (turns fullscreen off)\n");
	fprintf(stderr, "PAGEDOWN\t-> search for next (supported format) file and opens it\n");
	fprintf(stderr, "PAGEUP\t\t-> search for last (supported format) file and opens it\n");
	death();
}

void version(void)
{
	fprintf(stderr, "Version of %s is %s\n\n", PACKAGE, VERSION);
        author();
	death();
}

void none(void)
{
	fprintf(stderr, "Hit %s --help or -h` for more information.\n", PACKAGE);
	death();
}
