/*
 * print.c for dagrab
 *
 * DAGRAB - dumps digital audio from cdrom to riff wave files
 *
 * (C) 2000 Marcello Urbani <marcello@lumetel.it>
 * Miroslav Stibor <stibor@vertigo.fme.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include <linux/types.h>
#include <linux/cdrom.h>

#include "const.h"
#include "dagrab.h"
#include "cddb.h"
#include "version.h"

const int V_STAT[3] = { 0xffff, 0xfffe, 0 };
#define PERC_GRAPH 21		/* number of  pieces */

void dagrab_stderr(char *fmt, ...)
{
	char buf[2] = "\n";
	va_list pa;
	va_start(pa, fmt);

	if (fmt[0] == '\n')
		fmt++;
	else 
		buf[0] = 0;

	fprintf(stderr, "%s%s: ", buf, PROGNAME);
	vfprintf(stderr, fmt, pa);
	va_end(pa);
}

void fill_perc_graph(char *perc_graph, int perc)
{
	int i;
	static int perc_old = -1;

	if (perc == perc_old)
		return;

	for (i = PERC_GRAPH - 1; i >= 0; i--) {
		perc_graph[i] = ' ';
		if (perc - 50 / PERC_GRAPH > (100 * i) / PERC_GRAPH) {
			perc_graph[i] = '=';
		}
	}
	if (perc_graph[4] == '=') {
		i = sprintf(perc_graph + 1, "%i%%", perc);
		perc_graph[i + 1] = '=';
	}

	perc_old = perc;
}

int view_status(int id, const void *value)
{
	static int blocks, time_prev = 0, jitter_errs =
	    0, real_speed, overlap_err = 0, overlap =
	    OVERLAP, baddata, perc, sectors, overlap_err_old =
	    -1, baddata_old = -1;
	static float speed;
	static char *missing, err[2][4] = { "   ", "err" },
	    perc_graph[1 + PERC_GRAPH];

	switch (id) {
	case ID_BLOCKS:
		blocks = *((int *) value);
#ifdef DEBUG
		if (!opt_debug)
#endif
		{
			int time_now = time(NULL);
			if (time_now == time_prev)
				return 0;
			time_prev = time_now;
		}
		break;
	case ID_SPEED:
		/* Note: speed [%] does not refresh status view */
		speed = *((float *) value);
		return 0;
	case ID_REALSPEED:
		real_speed = *((int *) value);
		break;
	case ID_BADDATA:
		baddata = *((int *) value);
		if (baddata == baddata_old)
			return 0;
		baddata_old = baddata;
		break;
	case ID_JITTER:
		jitter_errs++;
		break;
	case ID_OVERLAP:
		if (*((int *) value) == V_STAT[OVERLAP_ERR])
			overlap_err = 1;
		else if (*((int *) value) == V_STAT[OVERLAP_OK])
			overlap_err = 0;
		else {
			/* Note: overlap does not refresh status view */
			overlap = *((int *) value);
			return jitter_errs;
		}
		if (overlap_err == overlap_err_old)
			return jitter_errs;
		overlap_err_old = overlap_err;
		break;
	case ID_SECTORS:
		sectors = *((int *) value);
		break;
	case ID_MISSING:
		missing = (char *) value;
		/* break; */
		return 0;
	case ID_NULL:
		blocks = jitter_errs = baddata = perc = sectors = 0;
		missing = NULL;
		speed = 0.0;
		fill_perc_graph(perc_graph, perc);
		break;
	case ID_PERC:
		perc = *((int *) value);
		if (opt_verbose)
			fill_perc_graph(perc_graph, perc);
		return 0;
		/* Note: ID_MISSING and ID_PERC does not refresh status view */
	}

	if (!opt_verbose)
		goto end_view_status;

	printf("%7i [%s] %5.2f/%-2i %5i  %s%3i   ", blocks, perc_graph,
	       speed, real_speed, sectors, err[overlap_err], overlap);

	printf((baddata ? "  %2i  " : "      "), baddata);

#ifdef DEBUG
	if (opt_debug)
		printf(opt_jitter_in ? "%2$5i   %1$8s\n" : "  off   %8s\n",
		       missing, jitter_errs);
	else
#endif
	printf(opt_jitter_in ? "%2$5i   %1$8s\r" : "  off   %8s\r",
	       missing, jitter_errs);

	fflush(stdout);

      end_view_status:
	return jitter_errs;
}

char *resttime(int sec)
{
	static char buf[10];
	sprintf(buf, "%02d:%02d:%02d", sec / 3600, (sec / 60) % 60,
		sec % 60);
	return buf;
}

void cd_disp_TOC(cd_trk_list * tl)
{
	int i, len, title_list[4] =
	    { KW_DISK, KW_AUTHOR, KW_GNR, KW_YEAR };
	char title[200];

	/****************************************************************
	 * DON'T FORGET TO UPDATE grab* SCRIPT, WHEN CHANGES HERE	*
	 ****************************************************************/
	if (opt_cddb) {
		for (i = 0; i < 4; i++) {
			int l;
			ExpandTempl(title,
				    kwords_p[l = title_list[i]].kw, 0, tl,
				    FALSE);
			if (title[0])
				printf("%s %s\n", kwords_p[l].printout,
				       title);
		}
	}

	printf("%5s %7s %6s %5s %8s %3s %s\n", "track", "start", "length",
	       "type", "duration", "MB", opt_cddb ? "Title" : "");

	for (i = tl->min; i <= tl->max; i++) {
		len =
		    tl->starts[i + 1 - tl->min] - tl->starts[i - tl->min];
		printf("%5d %7d %6d %5s %8s %3d", i,
		       tl->starts[i - tl->min], len,
		       tl->types[i - tl->min] ? "other" : "audio",
		       resttime(len / 75),
		       (len * CD_FRAMESIZE_RAW) >> 20);
		if (opt_cddb) {
			cddb_gettitle(tl->cddb, title, 1 + i - tl->min);
			printf(" %s", title);
		}
		printf("\n");

	}
	printf("%5d %7d %6s %s\n" "CDDB DISCID: %lx\n",
	       CDROM_LEADOUT, tl->starts[i - tl->min], "-", "leadout",
	       cddb_discid(tl));
}

void show_help(int which)
{
	int i;
	printf("dagrab " DAGRAB_VERSION
	       " -- dumps digital audio from IDE CD-ROM to riff wave files\n"
	       "Usage: dagrab [options] [track list | all]\nOptions:\n"
	       "\t-v\tverbose execution %s" "\t-i\tdisplay track list"
	       "\t--examples\texamples of using\n",
	       which == SHORTHELP ? "\t--longhelp\tlong help\n" :
	       "\t--help\t\tshort help\n");
	if (which == LONGHELP)
		printf("\t-d device\tset cdrom device (default=%s)\n"
		       "\t-n sectors\tsectors per request (%i); beware, higher values can\n"
		       "\t\t\t*improve performance*, but not all drives works fine\n",
		       CDDEVICE, N_BUF);

	printf("\t-J\t\tturn jitter correction filter on\n");
	if (which == LONGHELP)
		printf
		    ("\t-j delta\tdelta for jitter correction filter (%i)\n",
		     DELTA);

	printf
	    ("\t-f file\t\tset output file name: (-f - outputs to stdout)\n"
	     "\t\t\t\tembed %%02d for track numbering (no CDDB mode)\n"
	     "\t\t\t\tor variables in CDDB mode%s\n"
	     "%s"
	     "\t-e string\texecutes string for every copied track\n"
	     "\t\t\t\tembed %%s for track's filename (also see -f)\n"
	     "\t-C or -N\tuse CDDB name, changes behavior of -f's parameter\n"
	     "\t-H host\t\tCDDB server and port (%s:%d)\n"
	     "\t-D dir\t\tbase of local CDDB database\n",
	     which == SHORTHELP ? " (see --longhelp)" : " (see below)",
	     which == LONGHELP ? 
	     "\t-m mode\t\tdefault mode for files (octal number)\n"
	     "\t-s\t\tenable free space checking before dumping a track\n"
	     : "", CDDB_HOST, CDDB_PORT);

	if (which == SHORTHELP)
		return;

	printf
	    ("\t-S\t\tsave new CDDB data in local database (implies -C)\n"
	     "\n\tCDDB variables for -f and -e: (use lowcases for removing slashes)\n");
	for (i = KW_MAX; i >= 0; i--)
		printf("\t\t%s %s\n", (kwords_p + i)->kw,
		       (kwords_p + i)->desc);
}

void bad_par(int *real, int min, int max, char *mes)
{
	static char lh[2][5] = { "low", "high" };

	if (*real < min) {
		*real = min;
	} else if (*real > max) {
		*real = max;
	} else
		return;

	dagrab_stderr("%s too %s, setting to %i\n",
		      mes, lh[*real == max], *real);
}

void show_examples()
{
	puts
	    ("Examples of using the dagrab (using grab* script is strongly recommended):\n"
	     "$ dagrab -i -C\n"
	     "  Lists all tracks of the CD using the cddb archive.\n" "\n"
	     "$ dagrab -iC -D /tmp/cddb\n"
	     "  Lists all tracks using the cddb archive, that is in /tmp/cddb directory.\n" "\n"
	     "$ dagrab 3 -f file\%02d\n"
	     "  Dumps 3rd track into file03 without jitter correction (recommended only\n"
	     "  for perfect CD-ROMs).\n" "\n"
	     "$ dagrab 1 -J -v\n"
	     "  Dumps 1st track into track01.wav with jitter correction, verbose output.\n"
	     "  If you still can hear cracks, use lower delta with -j option.\n" "\n" 
	     "$ dagrab 1 -Jv -n 128\n"
	     "  As above, but gets 128 sectors per request. Should be *faster*, but there\n"
	     "  are some devices that do not work fine.\n" "\n"
	     "$ dagrab 3-5 -f - | tplay\n"
	     "  Plays 3rd to 5th track through the tplay.\n" "\n"
	     "$ dagrab all -J -f - | lame - CD.mp3\n"
	     "  Dumps all tracks (with jitter correction) and encodes to one big mp3 file\n"
	     "  (using the lame).\n" "\n"
	     "$ dagrab all -JN -D /tmp/cddb  -e 'lame -hk \"%s\" \"%s.mp3\"; rm \"%s\"'\n"
	     "  Dumps each track with jitter correction and then encodes to mp3 file. The\n"
	     "  files will be named by means of the cddb archive in /tmp/cddb directory.\n"
	     "  (02-Put_Down_That_Weapon.mp3)\n" "\n"
	     "$ dagrab all -JN -f '@NUM. @TRK' -e \"lame -hk --tt '@TRK' --ta '@AUT' --tl '@DIS' --tg '@GNR' --ty '@YER' --tn '@NUM' '%s' '%s.mp3'; rm '%s'\"\n"
	     "  Like above (02. Put Down That Weapon.mp3) and lame will add an id3 tag.\n" "\n"
	     "$ dagrab all -JN -f '@num.@trk' -e \"oggenc -q3 --title '@TRK' --artist '@AUT' --album '@DIS' --genre '@GNR' --date '@YER' --tracknum '@NUM' '%s' -o '%s.ogg'; rm '%s'\"\n"
	     "  Now using smart filenames (02.Put_Down_That_Weapon.ogg)."
);
}
