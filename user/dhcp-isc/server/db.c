/* db.c

   Persistent database management routines for DHCPD... */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#ifndef EMBED
#ifndef lint
static char copyright[] =
"$Id: db.c,v 1.9 2005/03/29 07:03:51 philipc Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */
#endif

#include "dhcpd.h"
#include <config/autoconf.h>
#if CONFIG_USER_FLATFSD_FLATFSD
#include "nettel.h"
#endif

/*#define DEBUG*/

static FILE *db_file;

static int counting = 0;
static int count = 0;
static TIME write_time;

/* Write the specified lease to the current lease database file. */

int write_lease (lease)
	struct lease *lease;
{
	struct tm *t;
	char tbuf [64];
	int i;

#ifdef DEBUG
	syslog(LOG_INFO, "write_lease(%s)\n", piaddr (&lease -> ip_addr));
#endif

	if (counting)
		++count;
	fprintf (db_file, "lease %s {\n", piaddr (&lease -> ip_addr));

	t = gmtime (&lease -> starts);
	sprintf (tbuf, "%d %d/%02d/%02d %02d:%02d:%02d;",
		 t -> tm_wday, t -> tm_year + 1900,
		 t -> tm_mon + 1, t -> tm_mday,
		 t -> tm_hour, t -> tm_min, t -> tm_sec);
	fprintf (db_file, "\tstarts %s\n", tbuf);

	t = gmtime (&lease -> ends);
	sprintf (tbuf, "%d %d/%02d/%02d %02d:%02d:%02d;",
		 t -> tm_wday, t -> tm_year + 1900,
		 t -> tm_mon + 1, t -> tm_mday,
		 t -> tm_hour, t -> tm_min, t -> tm_sec);
	fprintf (db_file, "\tends %s", tbuf);

	if (lease -> hardware_addr.hlen) {
		fprintf (db_file, "\n\thardware %s %s;",
			 hardware_types [lease -> hardware_addr.htype],
			 print_hw_addr (lease -> hardware_addr.htype,
					lease -> hardware_addr.hlen,
					lease -> hardware_addr.haddr));

		/*TO DO - we might want to check that we don't overflow the hardware type*/
	}
	if (lease -> uid_len) {
		int i;
		fprintf (db_file, "\n\tuid %2.2x", lease -> uid [0]);
		for (i = 1; i < lease -> uid_len; i++) {
			fprintf (db_file, ":%2.2x", lease -> uid [i]);
		}
		putc (';', db_file);
	}
	if (lease -> flags & BOOTP_LEASE) {
		fprintf (db_file, "\n\tdynamic-bootp;");
	}
	if (lease -> flags & ABANDONED_LEASE) {
		fprintf (db_file, "\n\tabandoned;");
	}
	if (lease -> client_hostname) {
		for (i = 0; lease -> client_hostname [i]; i++)
			if (lease -> client_hostname [i] < 33 ||
			    lease -> client_hostname [i] > 126)
				goto bad_client_hostname;
		fprintf (db_file, "\n\tclient-hostname \"%s\";",
			 lease -> client_hostname);
	}
       bad_client_hostname:
	if (lease -> hostname) {
		for (i = 0; lease -> hostname [i]; i++)
			if (lease -> hostname [i] < 33 ||
			    lease -> hostname [i] > 126)
				goto bad_hostname;
		fprintf (db_file, "\n\thostname \"%s\";",
			 lease -> hostname);
	}
       bad_hostname:
	fputs ("\n}\n", db_file);
	fflush(db_file);

	if (ferror(db_file)) {
		warn ("write_lease: unable to write lease %s",
		      piaddr (&lease -> ip_addr));

#ifdef EMBED
		/* new_lease_file() will not return if it can't fix the problem */
		new_lease_file();

		warn("Successfully reaped empty space in leases files");
#else
		return 0;
#endif
	}
	return 1;
}

/* Commit any leases that have been written out... */

int commit_leases ()
{
	/* Commit any outstanding writes to the lease database file.
	   We need to do this even if we're rewriting the file below,
	   just in case the rewrite fails. */
	fflush (db_file);

#ifdef DEBUG
	syslog(LOG_INFO, "commit_leases()\n");
#endif

	if (ferror(db_file)) {
		warn ("commit_leases: unable to commit: %m");

#ifdef EMBED
		/* new_lease_file() will not return if it can't fix the problem */
		new_lease_file();

		warn("Successfully reaped empty space in leases files");

		return 1;
#else
		return 0;
#endif
	}

	if (fsync (fileno (db_file)) < 0) {
		note ("commit_leases: unable to commit: %m");
		return 0;
	}

	/* If we've written more than fifty leases or if
	   we haven't rewritten the lease database in over an
	   hour, rewrite it now. */
	if (count > 50 || (count && cur_time - write_time > 3600)) {
		count = 0;
		write_time = cur_time;
		new_lease_file ();
	}
	return 1;
}

void db_startup ()
{
	/* Read in the existing lease file... */
	read_leases ();

	GET_TIME (&write_time);
	new_lease_file ();
}

void new_lease_file ()
{
#ifdef EMBED
	static int retrying = 0;
	int db_fd;

	/* If we have a lease file open, truncate it and try to rewrite it.
	 * Otherwise open in and write it.
	 */
	if (db_file) {
		fclose(db_file);
		db_file = 0;
	}

#ifdef DEBUG
	syslog(LOG_INFO, "new_lease_file() creating new lease file %s\n", path_dhcpd_db);
#endif

	db_fd = open(path_dhcpd_db, O_WRONLY | O_TRUNC | O_CREAT, 0664);
	if (db_fd >= 0) {
		db_file = fdopen(db_fd, "w");
	}
	if (!db_file) {
		/* Presumably we ran out of config space */
#ifdef DEBUG
		int save_errno = errno;

		syslog(LOG_INFO, "new_lease_file() failed to create lease file: %s\n", strerror(errno));

		errno = save_errno;
#endif

		if (errno == ENOSPC) {
#ifdef DEBUG
			syslog(LOG_INFO, "new_lease_file() failed to create %s: %m\n", path_dhcpd_db);
#endif
#if CONFIG_USER_FLATFSD_FLATFSD
			config_exhausted();
#endif
		}
		else {
			error ("Can't create new lease file: %m");
		}
	}

#ifdef DEBUG
	syslog(LOG_INFO, "new_lease_file() opened new lease file OK\n");
#endif

	/* If we were called recursively, we have to give up */
	if (retrying) {
#ifdef DEBUG
		syslog(LOG_INFO, "new_lease_file() called recursively, so failing\n");
#endif
#if CONFIG_USER_FLATFSD_FLATFSD
		config_exhausted();
#endif
	}

	/* OK. At this point db_file is empty and ready for leases */

	/* Write out all the leases that we know of... */
	counting = 0;
	retrying = 1;

	/* write_leases() will call commit_leases() and/or write_lease() which will
	 * call us again if anything fails
	 */
	write_leases();
	counting = 1;
	retrying = 0;

#if CONFIG_USER_FLATFSD_FLATFSD
	commitChanges();
#endif /* CONFIG_USER_FLATFSD_FLATFSD */
#else
	char newfname [512];
	char backfname [512];
	TIME t;
	int db_fd;

	/* If we already have an open database, close it. */
	if (db_file) {
		fclose (db_file);
	}

	/* Make a temporary lease file... */
	GET_TIME (&t);
	sprintf (newfname, "%s.%d", path_dhcpd_db, (int)t);
	db_fd = open (newfname, O_WRONLY | O_TRUNC | O_CREAT, 0664);
	if (db_fd < 0) {
		error ("Can't create new lease file: %m");
	}
	if ((db_file = fdopen (db_fd, "w")) == NULL) {
		error ("Can't fdopen new lease file!");
	}

	/* Write an introduction so people don't complain about time
	   being off. */
	fprintf (db_file, "# All times in this file are in UTC (GMT), not %s",
		 "your local timezone.   This is\n");
	fprintf (db_file, "# not a bug, so please don't ask about it.   %s",
		 "There is no portable way to\n");
	fprintf (db_file, "# store leases in the local timezone, so please %s",
		 "don't request this as a\n");
	fprintf (db_file, "# feature.   If this is inconvenient or %s",
		 "confusing to you, we sincerely\n");
	fprintf (db_file, "# apologize.   Seriously, though - don't ask.\n");
	fprintf (db_file, "# The format of this file is documented in the %s",
		 "dhcpd.leases(5) manual page.\n\n");

	/* Write out all the leases that we know of... */
	counting = 0;
	write_leases ();

	/* Get the old database out of the way... */
	sprintf (backfname, "%s~", path_dhcpd_db);
	if (unlink (backfname) < 0 && errno != ENOENT)
		error ("Can't remove old lease database backup %s: %m",
		       backfname);
	if (link (path_dhcpd_db, backfname) < 0)
		error ("Can't backup lease database %s to %s: %m",
		       path_dhcpd_db, backfname);
	
	/* Move in the new file... */
	if (rename (newfname, path_dhcpd_db) < 0)
		error ("Can't install new lease database %s to %s: %m",
		       newfname, path_dhcpd_db);
	counting = 1;
#endif
}
