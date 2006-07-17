/*
 * cddb.c for dagrab
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pwd.h>
#include <dirent.h>
#include <ctype.h>

#include <linux/cdrom.h>

#include "dagrab.h"
#include "const.h"
#include "version.h"
#include "print.h"

static int cddb_sock;
extern char opt_filter;

int cddb_sum(int n)
{
	int ret = 0;
	n /= 75;		/*elimina i frames */

	while (n > 0) {
		ret += n % 10;
		n /= 10;
	}
	return ret;
}

unsigned long cddb_discid(cd_trk_list * tl)
{
	int i, t, n = 0;

	for (i = tl->min; i <= tl->max; i++)
		n += cddb_sum(tl->starts[i - tl->min] + CD_MSF_OFFSET);
	t = (tl->starts[tl->max - tl->min + 1] - tl->starts[0]) / 75;

	return (n % 0xff) << 24 | t << 8 | (tl->max - tl->min + 1);
}

/* int make_socket (unsigned short int port,unsigned int addr) */
int make_socket(unsigned short int port, struct hostent *addr)
{
	int sock;
	struct sockaddr_in name;
	/* Create the socket. */
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror(PROGNAME);
		exit(EXIT_FAILURE);
	}
	/* Give the socket a name. */
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
/*  name.sin_addr.s_addr = htonl (addr); */
	memcpy(&name.sin_addr, addr->h_addr, addr->h_length);
	if (connect(sock, (struct sockaddr *) &name, sizeof(name))) {
		perror(PROGNAME);
		exit(EXIT_FAILURE);
	}
	return sock;
}

void cddb_sendcmd(char *c)
{
	write(cddb_sock, c, strlen(c));
}

int cddb_getresp(char *c, int s, int type)
{
	int a;
	fd_set re, wr, ex;
	struct timeval to;
	to.tv_sec = 5;
	to.tv_usec = 0;
	FD_ZERO(&re);
	FD_ZERO(&wr);
	FD_ZERO(&ex);
	FD_SET(cddb_sock, &re);
	select(cddb_sock + 1, &re, &wr, &ex, &to);
	a = read(cddb_sock, c, s);
	if (a > 0)
		c[a] = 0;
	if (c[0] != '2' && type == 1)
		return -1;
	else
		return a;
}

int cddb_handshake(void)
{
	struct passwd *pw;
	char *un, *hn, hn1[100], buf[2001];
	struct hostent *he, *hent;
	/* get the address */
	hent = gethostbyname(opt_cddb_host);
	if (hent == NULL)
		return 1;
	cddb_sock = make_socket(opt_cddb_port, hent);
	if (cddb_getresp(buf, 2000, 1) < 0)
		return 1;
	/* Get login name from the password file if possible */
	if ((pw = getpwuid(getuid())) != NULL)
		un = pw->pw_name;
	else
		/* Try the LOGNAME environment variable */
	if ((un = (char *) getenv("LOGNAME")) == NULL)
		/* Try the USER environment variable */
		un = (char *) getenv("USER");
	if (un == NULL)
		un = "unknown";
	if ((gethostname(hn1, 99) < 0)
	    || ((he = gethostbyname(hn1)) == NULL) || (he->h_name == NULL))
		hn = "unknown";
	else
		hn = (char *) he->h_name;
	sprintf(buf, "cddb hello %s %s %s %s\n", un, hn, PROGNAME,
		DAGRAB_VERSION);
	cddb_sendcmd(buf);
	if (cddb_getresp(buf, 2000, 1) < 0)
		return 1;
	return 0;
}

int cddb_query(char *qs, char **id, char **gnr)
{
	char buf[2001], *p, *q;

	sprintf(buf, "cddb query %s\n", qs);
	cddb_sendcmd(buf);
	if (cddb_getresp(buf, 2000, 1) < 0)
		return 1;
	p = buf + 4;
	if (buf[1] == '1') {
		dagrab_stderr("cddb inexact matches found, picking first\n");
		p = strchr(buf, '\n') + 1;
	}
	q = strchr(p, ' ');
	*q = 0;
	*gnr = strdup(p);
	p = q + 1;
	q = strchr(p, ' ');
	*q = 0;
	*id = strdup(p);
	p = q + 1;
	if ((buf[1] == '1') && (p[strlen(p) - 3] != '.'))
		do
			cddb_getresp(buf, 2000, 1);
		while (buf[strlen(buf) - 3] != '.');
	return 0;
}

int cddb_getdesc(char *gnr, char *id, char *data, int len)
{
	char buf[100];
	int i, a;
	char *q, *p, t[len];

	sprintf(buf, "cddb read %s %s\n", gnr, id);
	cddb_sendcmd(buf);
	t[0] = 0;
	a = i = 0;
	if ((i = cddb_getresp(t + a, len - a, 1)) < 0) {
		return -1;
	}
	a = i;
	while (t[a - 3] != '.') {
		i = cddb_getresp(t + a, len - a, 2);
		if (i < 0)
			return -1;
		a += i;
	}
	t[a - 3] = 0;
	cddb_sendcmd("quit\n");
	close(cddb_sock);
/* printf("%s",t); */
	q = data;
	p = t;
	while (*p++ != '\n');
	/* while ((*q=*p++)!=0) if(*q!='\r')q++; */
	while (*p)
		if ((*q = *p++) != '\r')
			q++;

	return q - data;
}

#define GET_GENRE (-1)
#define GET_YEAR  (-2)
#define GET_YEAR2 (-3)

int cddb_gettitle(char *data, char *title, int n)
{
	char *p = data, *q = title;
	int i, nn = -1;
	if (n == GET_YEAR2) {
		n = GET_YEAR;
		p = strstr(p, "\nEXTD");
		if (p) {
			char *pp = strchr(++p, '\n');
			p = strstr(p, "YEAR: ");
			if (p && (pp > p || !pp)) {
				memcpy(--p, "\nDYEAR=", 7);
			}
		}
		p = data;
	}
	if (n == GET_GENRE || n == GET_YEAR) {
		p = strstr(p, n == GET_GENRE ? "\nDGENR" : "\nDYE");
		if (p++)
			goto dump_title;
		else 
			return 1;
	}

	do {
		p = strstr(p, "\nDTIT");
		if (p) {
			nn++;
			p++;
		} else
			break;
	} while (1);

	if (n)
		n += nn;

	p = data;

	for (i = n; i >= 0; i--) {
		p = strstr(p, "TITLE");
		if (p == NULL) {
			title[0] = '\0';
			return 1;
		}
		else
			p += 2;
	}
dump_title:
	p = strchr(p, '=') + 1;
	while (p && *p != '\n' && *p != 0) {
		*q = *p++;
		q++;
	}
	if (!p || (*p == 0))
		return 1;

	*q = 0;
	while (--q > title && (!isprint(*q) || strpbrk(q, "-_ \t/")))
		*q = 0;
	if (q <= title)
		return 1;
	return 0;
}

int cddb_check(cd_trk_list * tl, char *cddb)
{
	char title[200];
	int i;
	for (i = tl->min - 1; i <= tl->max; i++) {
		if (cddb_gettitle(cddb, title, 1 + i - tl->min))
			return 1;
	}
	return 0;
}

char *cddb_getdir(char *str)
{
	static char path[500];

	char *p = getenv("XMCD_LIBDIR");
	sprintf(path, "%s%s", opt_cddb_path ? opt_cddb_path :
	        (p ? p : CDDB_PATH), str);
	return path;
}

int cddb_main(cd_trk_list * tl)
{
	FILE *f;
	DIR *d;
	struct dirent *e;
	char *id2, *p, *cddb, *loc;
	int i, cddbs, locs = 0;
	char id[12], *path, path2[500];
	cddb = malloc(CDDB_MAX);
	loc = malloc(CDDB_MAX);
	if (cddb == NULL || loc == NULL) {
		return -1;
	}
	loc[0] = cddb[0] = 0;
	sprintf(id, "%lx", cddb_discid(tl));

	for (i = 2, path = cddb_getdir("/cddb/"); i; i--, path = cddb_getdir(""))
		if ((d = opendir(path)) != NULL) {
			while ((e = readdir(d)) != NULL) {
				sprintf(path2, "%s/%s/%s", path, e->d_name,
					id);
				f = fopen(path2, "r");
				if (f != NULL) {
					locs = fread(loc, 1, CDDB_MAX, f);
					tl->gnr = strdup(e->d_name);
					break;
				}
			}
			break;
		}

	if (!cddb_check(tl, loc)) {
		if (opt_save) {
			opt_save = 0;
			dagrab_stderr(
				"using cddb entry found in local database\n");
		}
		tl->cddb = loc;
		tl->cddb_size = locs;
		free(cddb);
		return 0;
	} else {
		if (cddb_handshake()) {
			dagrab_stderr("error in cddb handshaking\n");
			goto fail_and_free;
		}
		p = path2;
		p += sprintf(p, "%s %d", id, tl->max - tl->min + 1);
		for (i = tl->min; i <= tl->max; i++)
			p += sprintf(p, " %d",
				    tl->starts[i - tl->min] + CD_MSF_OFFSET);
		p += sprintf(p, " %d\n",
			    (tl->starts[tl->max - tl->min + 1] -
			     tl->starts[0]) / 75);
		if (!cddb_query(path2, &id2, &tl->gnr)) {
			if ((cddbs =
			     cddb_getdesc(tl->gnr, id2, cddb, CDDB_MAX)) >= 0) {
				if (!cddb_check(tl, cddb)) {
					tl->cddb = cddb;
					tl->cddb_size = cddbs;
					free(loc);
					return 0;
				}
			}
		}
	}
fail_and_free:
	free(cddb);
	free(loc);
	return -1;
}

void ExpandVar(int kw, int lowcase, char *out, int tn,
	       cd_trk_list * tl, int is_path)
{
	char tmp[BLEN + 1];
	char *p;

	switch (kw) {
	case KW_TRACK:
		cddb_gettitle(tl->cddb, out, tn);
		break;
	case KW_FULLD:
		cddb_gettitle(tl->cddb, out, 0);
		break;
	case KW_AUTHOR:
		cddb_gettitle(tl->cddb, tmp, 0);
		if ((p = strchr(tmp, '/')) != NULL) {
			*p = 0;
			strcpy(out, tmp);
		} else
			*tmp = *out = 0;
		break;
	case KW_DISK:
		cddb_gettitle(tl->cddb, tmp, 0);
		if ((p = strchr(tmp, '/')) != NULL) {
			while (*(++p) == ' ' && *p);
			strcpy(out, p);
		} else
			strcpy(out, tmp);
		break;
	case KW_GNR:
		if (cddb_gettitle(tl->cddb, out, GET_GENRE)) {
			strcpy(out, tl->gnr);
			out[0] -= 32;
		}
		break;
	case KW_YEAR:
		if (cddb_gettitle(tl->cddb, out, GET_YEAR))
			if (cddb_gettitle(tl->cddb, out, GET_YEAR2))
				out[0] = '\0';
		if (strlen(out) > 4)
			out[4] = 0;
		break;
	case KW_NUM:
		sprintf(out, "%02d", tn);
		break;
	default:
		*out = 0;
		break;
	}

	p = out + strlen(out) - 1;
	while (p > out && *p == ' ')
		*(p--) = 0;
	if (is_path) {
		/* Remove "/:*<>?\|" when filenames */
		for (p = out; (p = strpbrk(p, "/:*<>?\\|")); p++) {
			switch (p[0]) {
			case '?':
				memmove(p, p + 1, strlen(p));
				break;
			case '*':
				p[0] = '+';
				break;
			case ':':
				p[0] = ';';
				break;
			case '<':
				p[0] = '(';
				break;
			case '>':
				p[0] = ')';
				break;
			case '|':
				p[0] = '#';
				break;
			default:
				p[0] = '-';
			}
		}
	}

	if (opt_filter)
		for (p = out; *p != 0; p++)
			if (p[0] == '\'')
				p[0] = '`';

	if (lowcase) {
		for (p = out; *p != 0; p++) {
			if (!isprint(((unsigned char*) p)[0])) {
				memmove(p, p + 1, strlen(p));
				p--;
			}
			if (*p == ' ' || *p == '`' || *p == '"' || *p == '\'')
				*p = '_';
		}
	}
}

char *SearchKw(char *str, char *kw)
{
	char *s1, *s2;
	char lc[10];
	strcpy(lc, kw);
	s1 = lc;
	while (*s1) {
		*s1 = tolower(*s1);
		s1++;
	}
	s1 = strstr(str, kw);
	s2 = strstr(str, lc);

	return (s2 != NULL && ((s1 == NULL) || (s2 < s1))) ? s2 : s1;
}

void TerminateTempl(char *inp)
{
	int i, j, len = strlen(inp);
	char *tmp = inp, *out;

	for (i = KW_MAX; i >= 0; i--) {
		out = inp;
		while (out - inp < len) {
			tmp = SearchKw(out, (kwords_p + i)->kw);
			if (!tmp)
				break;
			
			for (j = strlen((kwords_p + i)->kw) - 1; j >= 0; j--)
				tmp[j] = ' ';
			out = tmp + strlen((kwords_p + i)->kw);
		}
	}
}

void ExpandTempl(char *out, char *templ, int tn, cd_trk_list * tl, int is_path)
{
	char *tpidx, *outidx, *tmp, *tmp2;
	char varval[2000];
	int vart, len, i;
	tpidx = templ;
	outidx = out;
	while (tpidx != NULL && *tpidx != 0) {
		vart = -1;
		tmp = NULL;
		tmp2 = NULL;
		for (i = KW_MAX; i >= 0; i--) {
			tmp = SearchKw(tpidx, (kwords_p + i)->kw);
			if (tmp != NULL && (tmp < tmp2 || tmp2 == NULL)) {
				tmp2 = tmp;
				vart = i;
			}
		}

		if (vart >= 0) {
			len = tmp2 - tpidx;
			ExpandVar((kwords_p + vart)->idx,
				  islower(*(tmp2 + 1)), varval, tn, tl,
				  is_path);
			strncpy(outidx, tpidx, len);
			outidx += len;
			tpidx = tmp2 + strlen((kwords_p + vart)->kw);
			strcpy(outidx, varval);
			outidx += strlen(varval);
		} else {
			strcpy(outidx, tpidx);
			tpidx = NULL;
		}
	}
}
