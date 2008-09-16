/*
 *
 *  Audio/Video Distribution Transport Protocol (AVDTP) utility
 *
 *  Copyright (C) 2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>

#include "avdtp.h"

static void cmd_connect(bdaddr_t *src, bdaddr_t *dst, uint8_t seid)
{
	avdtp_t *av;
	int err;

	av = avdtp_create();
	if (!av) {
		fprintf(stderr, "Can't create AVDTP object\n");
		exit(1);
	}

	err = avdtp_bind(av, src);
	if (err < 0) {
		fprintf(stderr, "Can't bind AVDTP service: %s\n", strerror(-err));
		avdtp_free(av);
		exit(1);
	}

	err = avdtp_discover(av, dst);
	if (err < 0) {
		fprintf(stderr, "Can't discover AVDTP endpoints: %s\n", strerror(-err));
		avdtp_free(av);
		exit(1);
	}

	err = avdtp_connect(av, dst, seid);
	if (err < 0) {
		fprintf(stderr, "Can't connect AVDTP endpoint: %s\n", strerror(-err));
		avdtp_free(av);
		exit(1);
	}

	sleep(1);

	avdtp_close(av);

	avdtp_free(av);
}

static void usage(void)
{
	printf("Audio/Video distribution test utility ver %s\n\n", VERSION);

	printf("Usage:\n"
		"\tavtest [options] <bdaddr>\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	bdaddr_t src, dst;
	int opt;

	bacpy(&src, BDADDR_ANY);

	while ((opt = getopt_long(argc, argv, "+h", main_options, NULL)) != -1) {
		switch(opt) {
		case 'h':
			usage();
			exit(0);

		default:
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		exit(1);
	}

	str2ba(argv[0], &dst);

	cmd_connect(&src, &dst, 1);

	return 0;
}
