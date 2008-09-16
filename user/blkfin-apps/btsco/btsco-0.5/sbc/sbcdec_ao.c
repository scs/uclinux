/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) decoder
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>

#include <ao/ao.h>

#include "sbc.h"

static void decode(char *filename)
{
	ao_device *dev;
	ao_sample_format fmt;
	unsigned char *stream;
	struct stat st;
	off_t filesize;
	sbc_t sbc;
	int fd, id, pos, streamlen, framelen;

	if (stat(filename, &st) < 0) {
		fprintf(stderr, "Can't get size of file %s: %s\n",
						filename, strerror(errno));
		return;
	}

	filesize = st.st_size;

	stream = malloc(st.st_size);
	if (!stream) {
		fprintf(stderr, "Can't allocate memory for %s: %s\n",
						filename, strerror(errno));
		return;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open file %s: %s\n",
						filename, strerror(errno));
		goto free;
	}

	if (read(fd, stream, st.st_size) != st.st_size) {
		fprintf(stderr, "Can't read content of %s: %s\n",
						filename, strerror(errno));
		close(fd);
		goto free;
	}

	close(fd);

	pos = 0;
	streamlen = st.st_size;

	id = ao_default_driver_id();
	if (id < 0) {
		fprintf(stderr, "No usable audio output device available\n");
		goto free;
	}

	sbc_init(&sbc, SBC_NULL);

	framelen = sbc_decode(&sbc, stream, streamlen);
	printf("%d Hz, %d channels\n", sbc.rate, sbc.channels);

	fmt.bits = 16;
	fmt.rate = sbc.rate;
	fmt.channels = sbc.channels;
	fmt.byte_format = AO_FMT_BIG;

	dev = ao_open_live(id, &fmt, NULL);
	if (!dev) {
		fprintf(stderr, "Can't open audio device: %s\n", strerror(errno));
		goto free;
	}

	while (framelen > 0) {
		ao_play(dev, sbc.data, sbc.len);
		pos += framelen;
		framelen = sbc_decode(&sbc, stream + pos, streamlen - pos);
	}

	ao_close(dev);

	sbc_finish(&sbc);

free:
	free(stream);
}

static void usage(void)
{
	printf("SBC decoder utility ver %s\n", VERSION);
	printf("Copyright (c) 2004  Marcel Holtmann\n\n");

	printf("Usage:\n"
		"\tsbcdec [options] file(s)\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\t-v, --verbose        Verbose mode\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "verbose",	0, 0, 'v' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int i, opt, verbose = 0;

	while ((opt = getopt_long(argc, argv, "+hv", main_options, NULL)) != -1) {
		switch(opt) {
		case 'h':
			usage();
			exit(0);

		case 'v':
			verbose = 1;
			break;

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

	ao_initialize();

	for (i = 0; i < argc; i++)
		decode(argv[i]);

	ao_shutdown();

	return 0;
}
