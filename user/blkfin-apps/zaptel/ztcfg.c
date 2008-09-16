/*
 * Configuration program for Zapata Telephony Interface
 *
 * Written by Mark Spencer <markster@linux-support.net>
 * Based on previous works, designs, and architectures conceived and
 * written by Jim Dixon <jim@lambdatel.com>.
 *
 * Copyright (C) 2001 Jim Dixon / Zapata Telephony.
 * Copyright (C) 2001 Linux Support Services, Inc.
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under thet erms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 * Primary Author: Mark Spencer <markster@linux-support.net>
 *
 */

#include <stdio.h> 
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include "ztcfg.h"
#include "tonezone.h"
#include "zaptel.h"

#define NUM_SPANS ZT_MAX_SPANS

/* Assume no more than 1024 dynamics */
#define NUM_DYNAMIC	1024

static int lineno=0;

static FILE *cf;

static char *filename=CONFIG_FILENAME;

#define DEBUG_READER (1 << 0)
#define DEBUG_PARSER (1 << 1)
#define DEBUG_APPLY  (1 << 2)
static int debug = 0;

static int errcnt = 0;

static int deftonezone = -1;

static struct zt_lineconfig lc[ZT_MAX_SPANS];

static struct zt_chanconfig cc[ZT_MAX_CHANNELS];

static struct zt_dynamic_span zds[NUM_DYNAMIC];

static char *sig[ZT_MAX_CHANNELS];		/* Signalling */

static int slineno[ZT_MAX_CHANNELS];	/* Line number where signalling specified */

static int spans=0;

static int fo_real = 1;

static int verbose = 0;

static int stopmode = 0;

static int numdynamic = 0;

static char zonestoload[ZT_TONE_ZONE_MAX][10];

static int numzones = 0;

static char *lbostr[] = {
"0 db (CSU)/0-133 feet (DSX-1)",
"133-266 feet (DSX-1)",
"266-399 feet (DSX-1)",
"399-533 feet (DSX-1)",
"533-655 feet (DSX-1)",
"-7.5db (CSU)",
"-15db (CSU)",
"-22.5db (CSU)"
};

static char *laws[] = {
	"Default",
	"Mu-law",
	"A-law"
};

static int error(char *fmt, ...)
{
	int res;
	static int shown=0;
	va_list ap;
	if (!shown) {
		fprintf(stderr, "Notice: Configuration file is %s\n", filename);
		shown++;
	}
	res = fprintf(stderr, "line %d: ", lineno);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	errcnt++;
	return res;
}

static void trim(char *buf)
{
	/* Trim off trailing spaces, tabs, etc */
	while(strlen(buf) && (buf[strlen(buf) -1] < 33))
		buf[strlen(buf) -1] = '\0';
}

static int parseargs(char *input, char *output[], int maxargs, char sep)
{
	char *c;
	int pos=0;
	c = input;
	output[pos++] = c;
	while(*c) {
		while(*c && (*c != sep)) c++;
		if (*c) {
			*c = '\0';
			c++;
			while(*c && (*c < 33)) c++;
			if (*c)  {
				if (pos >= maxargs)
					return -1;
				output[pos] = c;
				trim(output[pos]);
				pos++;
				output[pos] = NULL;
				/* Return error if we have too many */
			} else
				return pos;
		}
	}
	return pos;
}

int dspanconfig(char *keyword, char *args)
{
	static char *realargs[10];
	int argc;
	int res;
	int chans;
	int timing;
	argc = res = parseargs(args, realargs, 4, ',');
	if (res != 4) {
		error("Incorrect number of arguments to 'dynamic' (should be <driver>,<address>,<num channels>, <timing>)\n");
	}
	res = sscanf(realargs[2], "%d", &chans);
	if ((res == 1) && (chans < 1))
		res = -1;
	if (res != 1) {
		error("Invalid number of channels '%s', should be a number > 0.\n", realargs[2]);
	}

	res = sscanf(realargs[3], "%d", &timing);
	if ((res == 1) && (timing < 0))
		res = -1;
	if (res != 1) {
		error("Invalid timing '%s', should be a number > 0.\n", realargs[3]);
	}


	strncpy(zds[numdynamic].driver, realargs[0], sizeof(zds[numdynamic].driver));
	strncpy(zds[numdynamic].addr, realargs[1], sizeof(zds[numdynamic].addr));
	zds[numdynamic].numchans = chans;
	zds[numdynamic].timing = timing;
	
	numdynamic++;
	return 0;
}

int spanconfig(char *keyword, char *args)
{
	static char *realargs[10];
	int res;
	int argc;
	int span;
	int timing;
	argc = res = parseargs(args, realargs, 7, ',');
	if ((res < 5) || (res > 7)) {
		error("Incorrect number of arguments to 'span' (should be <spanno>,<timing>,<lbo>,<framing>,<coding>[, crc4 | yellow [, yellow]])\n");
	}
	res = sscanf(realargs[0], "%i", &span);
	if (res != 1) {
		error("Span number should be a valid span number, not '%s'\n", realargs[0]);
		return -1;
	}
	res = sscanf(realargs[1], "%i", &timing);
	if ((res != 1) || (timing < 0) || (timing > 15)) {
		error("Timing should be a number from 0 to 15, not '%s'\n", realargs[1]);
		return -1;
	}
	res = sscanf(realargs[2], "%i", &lc[spans].lbo);
	if (res != 1) {
		error("Line build-out (LBO) should be a number from 0 to 7 (usually 0) not '%s'\n", realargs[2]);
		return -1;
	}
	if ((lc[spans].lbo < 0) || (lc[spans].lbo > 7)) {
		error("Line build-out should be in the range 0 to 7, not %d\n", lc[spans].lbo);
		return -1;
	}
	if (!strcasecmp(realargs[3], "d4")) {
		lc[spans].lineconfig |= ZT_CONFIG_D4;
		lc[spans].lineconfig &= ~ZT_CONFIG_ESF;
		lc[spans].lineconfig &= ~ZT_CONFIG_CCS;
	} else if (!strcasecmp(realargs[3], "esf")) {
		lc[spans].lineconfig |= ZT_CONFIG_ESF;
		lc[spans].lineconfig &= ~ZT_CONFIG_D4;
		lc[spans].lineconfig &= ~ZT_CONFIG_CCS;
	} else if (!strcasecmp(realargs[3], "ccs")) {
		lc[spans].lineconfig |= ZT_CONFIG_CCS;
		lc[spans].lineconfig &= ~(ZT_CONFIG_ESF | ZT_CONFIG_D4);
	} else if (!strcasecmp(realargs[3], "cas")) {
		lc[spans].lineconfig &= ~ZT_CONFIG_CCS;
		lc[spans].lineconfig &= ~(ZT_CONFIG_ESF | ZT_CONFIG_D4);
	} else {
		error("Framing(T1)/Signalling(E1) must be one of 'd4', 'esf', 'cas' or 'ccs', not '%s'\n", realargs[3]);
		return -1;
	}
	if (!strcasecmp(realargs[4], "ami")) {
		lc[spans].lineconfig &= ~(ZT_CONFIG_B8ZS | ZT_CONFIG_HDB3);
		lc[spans].lineconfig |= ZT_CONFIG_AMI;
	} else if (!strcasecmp(realargs[4], "b8zs")) {
		lc[spans].lineconfig |= ZT_CONFIG_B8ZS;
		lc[spans].lineconfig &= ~(ZT_CONFIG_AMI | ZT_CONFIG_HDB3);
	} else if (!strcasecmp(realargs[4], "hdb3")) {
		lc[spans].lineconfig |= ZT_CONFIG_HDB3;
		lc[spans].lineconfig &= ~(ZT_CONFIG_AMI | ZT_CONFIG_B8ZS);
	} else {
		error("Coding must be one of 'ami', 'b8zs' or 'hdb3', not '%s'\n", realargs[4]);
		return -1;
	}
	if (argc > 5) {
		if (!strcasecmp(realargs[5], "yellow"))
			lc[spans].lineconfig |= ZT_CONFIG_NOTOPEN;
		else if (!strcasecmp(realargs[5], "crc4")) {
			lc[spans].lineconfig |= ZT_CONFIG_CRC4;
		} else {
			error("Only valid fifth arguments are 'yellow' or 'crc4', not '%s'\n", realargs[5]);
			return -1;
		}
	}
	if (argc > 6) {
		if (!strcasecmp(realargs[6], "yellow"))
			lc[spans].lineconfig |= ZT_CONFIG_NOTOPEN;
		else {
			error("Only valid sixth argument is 'yellow', not '%s'\n", realargs[6]);
			return -1;
		}
	}
	lc[spans].span = span;
	lc[spans].sync = timing;
	/* Valid span */
	spans++;
	return 0;
}

int apply_channels(int chans[], char *argstr)
{
	char *args[ZT_MAX_CHANNELS+1];
	char *range[3];
	int res,x, res2,y;
	int chan;
	int start, finish;
	char argcopy[256];
	res = parseargs(argstr, args, ZT_MAX_CHANNELS, ',');
	if (res < 0)
		error("Too many arguments...  Max is %d\n", ZT_MAX_CHANNELS);
	for (x=0;x<res;x++) {
		if (strchr(args[x], '-')) {
			/* It's a range */
			strncpy(argcopy, args[x], sizeof(argcopy));
			res2 = parseargs(argcopy, range, 2, '-');
			if (res2 != 2) {
				error("Syntax error in range '%s'.  Should be <val1>-<val2>.\n", args[x]);
				return -1;
			}
			res2 =sscanf(range[0], "%i", &start);
			if (res2 != 1) {
				error("Syntax error.  Start of range '%s' should be a number from 1 to %d\n", args[x], ZT_MAX_CHANNELS - 1);
				return -1;
			} else if ((start < 1) || (start >= ZT_MAX_CHANNELS)) {
				error("Start of range '%s' must be between 1 and %d (not '%d')\n", args[x], ZT_MAX_CHANNELS - 1, start);
				return -1;
			}
			res2 =sscanf(range[1], "%i", &finish);
			if (res2 != 1) {
				error("Syntax error.  End of range '%s' should be a number from 1 to %d\n", args[x], ZT_MAX_CHANNELS - 1);
				return -1;
			} else if ((finish < 1) || (finish >= ZT_MAX_CHANNELS)) {
				error("end of range '%s' must be between 1 and %d (not '%d')\n", args[x], ZT_MAX_CHANNELS - 1, finish);
				return -1;
			}
			if (start > finish) {
				error("Range '%s' should start before it ends\n", args[x]);
				return -1;
			}
			for (y=start;y<=finish;y++)
				chans[y]=1;
		} else {
			/* It's a single channel */
			res2 =sscanf(args[x], "%i", &chan);
			if (res2 != 1) {
				error("Syntax error.  Channel should be a number from 1 to %d, not '%s'\n", ZT_MAX_CHANNELS - 1, args[x]);
				return -1;
			} else if ((chan < 1) || (chan >= ZT_MAX_CHANNELS)) {
				error("Channel must be between 1 and %d (not '%d')\n", ZT_MAX_CHANNELS - 1, chan);
				return -1;
			}
			chans[chan]=1;
		}		
	}
	return res;
}

int parse_idle(int *i, char *s)
{
	char a,b,c,d;
	if (s) {
		if (sscanf(s, "%c%c%c%c", &a,&b,&c,&d) == 4) {
			if (((a == '0') || (a == '1')) && ((b == '0') || (b == '1')) && ((c == '0') || (c == '1')) && ((d == '0') || (d == '1'))) {
				*i = 0;
				if (a == '1') 
					*i |= ZT_ABIT;
				if (b == '1')
					*i |= ZT_BBIT;
				if (c == '1')
					*i |= ZT_CBIT;
				if (d == '1')
					*i |= ZT_DBIT;
				return 0;
			}
		}
	}
	error("CAS Signalling requires idle definition in the form ':xxxx' at the end of the channel definition, where xxxx represent the a, b, c, and d bits\n");
	return -1;
}

static int parse_channel(char *channel, int *startchan)
{
	if (!channel || (sscanf(channel, "%i", startchan) != 1) || 
		(*startchan < 1)) {
		error("DACS requires a starting channel in the form ':x' where x is the channel\n");
		return -1;
	}
	return 0;
}

static int chanconfig(char *keyword, char *args)
{
	int chans[ZT_MAX_CHANNELS];
	int res = 0;
	int x;
	int master=0;
	int dacschan = 0;
	char *idle;
	bzero(chans, sizeof(chans));
	strtok(args, ":");
	idle = strtok(NULL, ":");
	if (!strcasecmp(keyword, "dacs") || !strcasecmp(keyword, "dacsrbs")) {
		res = parse_channel(idle, &dacschan);
	}
	if (!res)
		res = apply_channels(chans, args);
	if (res <= 0)
		return -1;
	for (x=1;x<ZT_MAX_CHANNELS;x++) 
		if (chans[x]) {
			if (slineno[x]) {
				error("Channel %d already configured as '%s' at line %d\n", x, sig[x], slineno[x]);
				continue;
			}
			if ((!strcasecmp(keyword, "dacs") || !strcasecmp(keyword, "dacsrbs")) && slineno[dacschan]) {
				error("DACS Destination channel %d already configured as '%s' at line %d\n", dacschan, sig[dacschan], slineno[dacschan]);
				continue;
			} else {
				cc[dacschan].chan = dacschan;
				cc[dacschan].master = dacschan;
				slineno[dacschan] = lineno;
			}
			cc[x].chan = x;
			cc[x].master = x;
			slineno[x] = lineno;
			if (!strcasecmp(keyword, "e&m")) {
				sig[x] = "E & M";
				cc[x].sigtype = ZT_SIG_EM;
			} else if (!strcasecmp(keyword, "e&me1")) {
				sig[x] = "E & M E1";
				cc[x].sigtype = ZT_SIG_EM_E1;
			} else if (!strcasecmp(keyword, "fxsls")) {
				sig[x] = "FXS Loopstart";
				cc[x].sigtype = ZT_SIG_FXSLS;
			} else if (!strcasecmp(keyword, "fxsgs")) {
				sig[x] = "FXS Groundstart";
				cc[x].sigtype = ZT_SIG_FXSGS;
			} else if (!strcasecmp(keyword, "fxsks")) {
				sig[x] = "FXS Kewlstart";
				cc[x].sigtype = ZT_SIG_FXSKS;
			} else if (!strcasecmp(keyword, "fxols")) {
				sig[x] = "FXO Loopstart";
				cc[x].sigtype = ZT_SIG_FXOLS;
			} else if (!strcasecmp(keyword, "fxogs")) {
				sig[x] = "FXO Groundstart";
				cc[x].sigtype = ZT_SIG_FXOGS;
			} else if (!strcasecmp(keyword, "fxoks")) {
				sig[x] = "FXO Kewlstart";
				cc[x].sigtype = ZT_SIG_FXOKS;
			} else if (!strcasecmp(keyword, "cas") || !strcasecmp(keyword, "user")) {
				if (parse_idle(&cc[x].idlebits, idle))
					return -1;
				sig[x] = "CAS / User";
				cc[x].sigtype = ZT_SIG_CAS;
			} else if (!strcasecmp(keyword, "dacs")) {
				/* Setup channel for monitor */
				cc[x].idlebits = dacschan;
				cc[x].sigtype = ZT_SIG_DACS;
				sig[x] = "DACS";
				/* Setup inverse */
				cc[dacschan].idlebits = x;
				cc[dacschan].sigtype = ZT_SIG_DACS;
				sig[dacschan] = "DACS";
				dacschan++;
			} else if (!strcasecmp(keyword, "dacsrbs")) {
				/* Setup channel for monitor */
				cc[x].idlebits = dacschan;
				cc[x].sigtype = ZT_SIG_DACS_RBS;
				sig[x] = "DACS w/ RBS";
				/* Setup inverse */
				cc[dacschan].idlebits = x;
				cc[dacschan].sigtype = ZT_SIG_DACS_RBS;
				sig[dacschan] = "DACS w/ RBS";
				dacschan++;
			} else if (!strcasecmp(keyword, "unused")) {
				sig[x] = "Unused";
				cc[x].sigtype = 0;
			} else if (!strcasecmp(keyword, "indclear") || !strcasecmp(keyword, "bchan")) {
				sig[x] = "Individual Clear channel";
				cc[x].sigtype = ZT_SIG_CLEAR;
			} else if (!strcasecmp(keyword, "clear")) {
				sig[x] = "Clear channel";
				if (master) {
					cc[x].sigtype = ZT_SIG_SLAVE;
					cc[x].master = master;
				} else {
					cc[x].sigtype = ZT_SIG_CLEAR;
					master = x;
				}
			} else if (!strcasecmp(keyword, "rawhdlc")) {
				sig[x] = "Raw HDLC";
				if (master) {
					cc[x].sigtype = ZT_SIG_SLAVE;
					cc[x].master = master;
				} else {
					cc[x].sigtype = ZT_SIG_HDLCRAW;
					master = x;
				}
			} else if (!strcasecmp(keyword, "nethdlc")) {
				sig[x] = "Network HDLC";
				if (master) {
					cc[x].sigtype = ZT_SIG_SLAVE;
					cc[x].master = master;
				} else {
					cc[x].sigtype = ZT_SIG_HDLCNET;
					master = x;
				}
			} else if (!strcasecmp(keyword, "fcshdlc")) {
				sig[x] = "HDLC with FCS check";
				if (master) {
					cc[x].sigtype = ZT_SIG_SLAVE;
					cc[x].master = master;
				} else {
					cc[x].sigtype = ZT_SIG_HDLCFCS;
					master = x;
				}
			} else if (!strcasecmp(keyword, "dchan")) {
				sig[x] = "D-channel";
				cc[x].sigtype = ZT_SIG_HDLCFCS;
			} else {
				fprintf(stderr, "Huh? (%s)\n", keyword);
			}
		}
	return 0;
}

static int setlaw(char *keyword, char *args)
{
	int res;
	int law;
	int x;
	int chans[ZT_MAX_CHANNELS];

	bzero(chans, sizeof(chans));
	res = apply_channels(chans, args);
	if (res <= 0)
		return -1;
	if (!strcasecmp(keyword, "alaw")) {
		law = ZT_LAW_ALAW;
	} else if (!strcasecmp(keyword, "mulaw")) {
		law = ZT_LAW_MULAW;
	} else if (!strcasecmp(keyword, "deflaw")) {
		law = ZT_LAW_DEFAULT;
	} else {
		fprintf(stderr, "Huh??? Don't know about '%s' law\n", keyword);
		return -1;
	}
	for (x=0;x<ZT_MAX_CHANNELS;x++) {
		if (chans[x])
			cc[x].deflaw = law;
	}
	return 0;
}

static int registerzone(char *keyword, char *args)
{
	if (numzones >= ZT_TONE_ZONE_MAX) {
		error("Too many tone zones specified\n");
		return 0;
	}
	strncpy(zonestoload[numzones++], args, sizeof(zonestoload[0]));
	return 0;
}

static int defaultzone(char *keyword, char *args)
{
	struct tone_zone *z;
	if (!(z = tone_zone_find(args))) {
		error("No such tone zone known: %s\n", args);
		return 0;
	}
	deftonezone = z->zone;
	return 0;
}

#if 0
static int unimplemented(char *keyword, char *args)
{
	fprintf(stderr, "Warning: '%s' is not yet implemented\n", keyword);
	return 0;
}
#endif

static void printconfig()
{
	int x,y;
	int ps;
	int configs=0;
	printf("\nZaptel Configuration\n"
	       "======================\n\n");
	for (x=0;x<spans;x++) 
		printf("SPAN %d: %3s/%4s Build-out: %s\n",
		       x+1, ( lc[x].lineconfig & ZT_CONFIG_D4 ? "D4" :
			      lc[x].lineconfig & ZT_CONFIG_ESF ? "ESF" :
			      lc[x].lineconfig & ZT_CONFIG_CCS ? "CCS" : "CAS" ),
			( lc[x].lineconfig & ZT_CONFIG_AMI ? "AMI" :
			  lc[x].lineconfig & ZT_CONFIG_B8ZS ? "B8ZS" :
			  lc[x].lineconfig & ZT_CONFIG_HDB3 ? "HDB3" : "???" ),
			lbostr[lc[x].lbo]);
	for (x=0;x<numdynamic;x++) {
		printf("Dynamic span %d: driver %s, addr %s, channels %d, timing %d\n",
		       x +1, zds[x].driver, zds[x].addr, zds[x].numchans, zds[x].timing);
	}
	if (verbose > 1) {
		printf("\nChannel map:\n\n");
		for (x=1;x<ZT_MAX_CHANNELS;x++) {
			if ((cc[x].sigtype != ZT_SIG_SLAVE) && (cc[x].sigtype)) {
				configs++;
				ps = 0;
				if ((cc[x].sigtype & __ZT_SIG_DACS) == __ZT_SIG_DACS)
					printf("Channel %02d %s to %02d", x, sig[x], cc[x].idlebits);
				else {
					printf("Channel %02d: %s (%s)", x, sig[x], laws[cc[x].deflaw]);
					for (y=1;y<ZT_MAX_CHANNELS;y++) 
						if (cc[y].master == x)  {
							printf("%s%02d", ps++ ? " " : " (Slaves: ", y);
						}
				}
				if (ps) printf(")\n"); else printf("\n");
			} else
				if (cc[x].sigtype) configs++;
		}
	} else 
		for (x=1;x<ZT_MAX_CHANNELS;x++) 
			if (cc[x].sigtype)
				configs++;
	printf("\n%d channels configured.\n\n", configs);
}

static struct handler {
	char *keyword;
	int (*func)(char *keyword, char *args);
} handlers[] = {
	{ "span", spanconfig },
	{ "dynamic", dspanconfig },
	{ "loadzone", registerzone },
	{ "defaultzone", defaultzone },
	{ "e&m", chanconfig },
	{ "e&me1", chanconfig },
	{ "fxsls", chanconfig },
	{ "fxsgs", chanconfig },
	{ "fxsks", chanconfig },
	{ "fxols", chanconfig },
	{ "fxogs", chanconfig },
	{ "fxoks", chanconfig },
	{ "rawhdlc", chanconfig },
	{ "nethdlc", chanconfig },
	{ "fcshdlc", chanconfig },
	{ "dchan", chanconfig },
	{ "bchan", chanconfig },
	{ "indclear", chanconfig },
	{ "clear", chanconfig },
	{ "unused", chanconfig },
	{ "cas", chanconfig },
	{ "dacs", chanconfig },
	{ "dacsrbs", chanconfig },
	{ "user", chanconfig },
	{ "alaw", setlaw },
	{ "mulaw", setlaw },
	{ "deflaw", setlaw },
};

static char *readline()
{
	static char buf[256];
	char *c;
	do {
		if (!fgets(buf, sizeof(buf), cf)) 
			return NULL;
		/* Strip comments */
		c = strchr(buf, '#');
		if (c)
			*c = '\0';
		trim(buf);
		lineno++;
	} while (!strlen(buf));
	return buf;
}

static void usage(char *argv0, int exitcode)
{
	char *c;
	c = strrchr(argv0, '/');
	if (!c)
		c = argv0;
	else
		c++;
	fprintf(stderr, 
		"Usage: %s [options]\n"
		"    Valid options are:\n"
		"  -c <filename>     -- Use <filename> instead of " CONFIG_FILENAME "\n"
		"  -h                -- Generate this help statement\n"
		"  -v                -- Verbose (more -v's means more verbose)\n"
		"  -t                -- Test mode only, do not apply\n"
		"  -s                -- Shutdown spans only\n"
	,c);
	exit(exitcode);
}

int main(int argc, char *argv[])
{
	int c;
	char *buf;
	char *key, *value;
	int x,found;
	int fd;
	while((c = getopt(argc, argv, "thc:vs")) != -1) {
		switch(c) {
		case 'c':
			filename=optarg;
			break;
		case 'h':
			usage(argv[0], 0);
			break;
		case '?':
			usage(argv[0], 1);
			break;
		case 'v':
			verbose++;
			break;
		case 't':
			fo_real = 0;
			break;
		case 's':
			stopmode = 1;
			break;
		}
	}
	cf = fopen(filename, "r");
	if (cf) {
		while((buf = readline())) {
			if (debug & DEBUG_READER) 
				fprintf(stderr, "Line %d: %s\n", lineno, buf);
			key = value = buf;
			while(value && *value && (*value != '=')) value++;
			if (value)
				*value='\0';
			if (value)
				value++;
			while(value && *value && (*value < 33)) value++;
			if (*value) {
				trim(key);
				if (debug & DEBUG_PARSER)
					fprintf(stderr, "Keyword: [%s], Value: [%s]\n", key, value);
			} else
				error("Syntax error.  Should be <keyword>=<value>\n");
			found=0;
			for (x=0;x<sizeof(handlers) / sizeof(handlers[0]);x++) {
				if (!strcasecmp(key, handlers[x].keyword)) {
					found++;
					handlers[x].func(key, value);
					break;
				}
			}
			if (!found) 
				error("Unknown keyword '%s'\n", key);
		}
		if (debug & DEBUG_READER)
			fprintf(stderr, "<End of File>\n");
		fclose(cf);
	} else {
		error("Unable to open configuration file '%s'\n", filename);
	}

	if (!errcnt) {
		if (verbose) {
			printconfig();
		}
		if (fo_real) {
			if (debug & DEBUG_APPLY) {
				printf("About to open Master device\n");
				fflush(stdout);
			}
			fd = open(MASTER_DEVICE, O_RDWR);
			if (fd < 0) 
				error("Unable to open master device '%s'\n", MASTER_DEVICE);
			else {
				for (x=0;x<numdynamic;x++) {
					/* destroy them all */
					ioctl(fd, ZT_DYNAMIC_DESTROY, &zds[x]);
				}
				if (stopmode) {
					for (x=0;x<spans;x++) {
						if (ioctl(fd, ZT_SHUTDOWN, &lc[x].span)) {
							fprintf(stderr, "Zaptel shutdown failed: %s\n", strerror(errno));
							close(fd);
							exit(1);
						}
					}
				} else {
					for (x=0;x<spans;x++) {
						if (ioctl(fd, ZT_SPANCONFIG, lc + x)) {
							fprintf(stderr, "ZT_SPANCONFIG failed on span %d: %s (%d)\n", lc[x].span, strerror(errno), errno);
							close(fd);
							exit(1);
						}
					}
					for (x=0;x<numdynamic;x++) {
						if (ioctl(fd, ZT_DYNAMIC_CREATE, &zds[x])) {
							fprintf(stderr, "Zaptel dynamic span creation failed: %s\n", strerror(errno));
							close(fd);
							exit(1);
						}
					}
					for (x=1;x<ZT_MAX_CHANNELS;x++) {
						if (debug & DEBUG_APPLY) {
							printf("Configuring device %d\n", x);
							fflush(stdout);
						}
						if (cc[x].sigtype && ioctl(fd, ZT_CHANCONFIG, &cc[x])) {
							fprintf(stderr, "ZT_CHANCONFIG failed on channel %d: %s (%d)\n", x, strerror(errno), errno);
							if (errno == EINVAL) {
								fprintf(stderr, "Did you forget that FXS interfaces are configured with FXO signalling\n"
									"and that FXO interfaces use FXS signalling?\n");
							}
							close(fd);
							exit(1);
						}
					}
					for (x=0;x<numzones;x++) {
						if (debug & DEBUG_APPLY) {
							printf("Loading tone zone for %s\n", zonestoload[x]);
							fflush(stdout);
						}
						if (tone_zone_register(fd, zonestoload[x]))
							error("Unable to register tone zone '%s'\n", zonestoload[x]);
					}
					if (debug & DEBUG_APPLY) {
						printf("Doing startup\n");
						fflush(stdout);
					}
					if (deftonezone > -1) {
						if (ioctl(fd, ZT_DEFAULTZONE, &deftonezone)) {
							fprintf(stderr, "ZT_DEFAULTZONE failed: %s (%d)\n", strerror(errno), errno);
							close(fd);
							exit(1);
						}
					}
					for (x=0;x<spans;x++) {
						if (ioctl(fd, ZT_STARTUP, &lc[x].span)) {
							fprintf(stderr, "Zaptel startup failed: %s\n", strerror(errno));
							close(fd);
							exit(1);
						}
					}
				}
				close(fd);
			}
		}
	} else {
		fprintf(stderr, "\n%d error(s) detected\n\n", errcnt);
		exit(1);
	}
	exit(0);
}
