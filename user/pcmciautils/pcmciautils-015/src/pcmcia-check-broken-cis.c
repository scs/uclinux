/*
 * pcmcia-check-broken-cis.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * (C) 1999             David A. Hinds
 * (C) 2005             Dominik Brodowski
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "cistpl.h"


#define FIRMWARE_PATH	"/lib/firmware"
#define CIS_PATH	"/etc/pcmcia/cis"
#define SOCKET_PATH	"/sys/class/pcmcia_socket/pcmcia_socket%d/cis"

struct needs_cis {
	unsigned long code;
	unsigned long ofs;
	char *info;
	char *cisfile;
};

#define NEEDS_CIS_ENTRY(_code, _ofs, _info, _cisfile) \
{ .code = _code, .ofs = _ofs, .info = _info, .cisfile = _cisfile, }

static const struct needs_cis cis_table[] = {
	/* "D-Link DE-650 Ethernet" */
	NEEDS_CIS_ENTRY(0x40, 0x0009, "D-Link PC Ethernet Card", "D-Link.cis"),
	/* "Linksys Ethernet E-CARD PC Ethernet Card */
	NEEDS_CIS_ENTRY(0x40, 0x0009, "E-CARD PC Ethernet Card", "E-CARD.cis"),
	{ },
};

int device_has_driver() {
	char *devpath, *path;
	struct stat sbuf;

	devpath = getenv("DEVPATH");
	if (!devpath)
		return ENODEV;
	path = alloca(strlen(devpath)+15);
	sprintf(path,"/sys/%s/driver", devpath);
	if (!stat(path,&sbuf)) {
		return 1;
	}
	return 0;
}

char *read_cis(char *cis_file, int *size) {
	char *cis_path;
	char *ret;
	int rc, cis_fd;
	struct stat sbuf;

	cis_path = alloca(strlen(FIRMWARE_PATH) + strlen(cis_file) + 2);
	sprintf(cis_path,"%s/%s", FIRMWARE_PATH, cis_file);
	cis_fd = open(cis_path, O_RDONLY);
	if (cis_fd == -1) {
		cis_path = alloca(strlen(CIS_PATH) + strlen(cis_file) + 2);
		sprintf(cis_path,"%s/%s", CIS_PATH, cis_file);
		if (cis_fd == -1) {
			rc = errno;
			errno = rc;
			return NULL;
		}
	}
	fstat(cis_fd, &sbuf);
	ret = malloc(sbuf.st_size);
	if (!ret) {
		rc = errno;
		close(cis_fd);
		errno = rc;
		return NULL;
	}
	if (read(cis_fd, ret, sbuf.st_size) != sbuf.st_size) {
		rc = errno;
		free(ret);
		close(cis_fd);
		errno = rc;
		return NULL;
	}
	close(cis_fd);
	*size = sbuf.st_size;
	return ret;
}

int write_cis(char *cis, int socket_no, int size) {
	char *cis_path;
	int cis_fd, count, rc;

	cis_path = alloca(strlen(SOCKET_PATH) + 2);
	sprintf(cis_path,SOCKET_PATH, socket_no);

	cis_fd = open(cis_path, O_RDWR);
	if (cis_fd == -1) {
		return errno;
	}

	count = 0;
	while (count < size) {
		int c;

		c = write(cis_fd, cis+count, size-count);
		if (c <= 0) {
			rc = errno;
			close(cis_fd);
			return rc;
		}
		count += c;
	}
	close(cis_fd);
	return 0;
}

int repair_cis(char *cis_file, int socket_no) {
	char *cis;
	int rc, size;

	if (device_has_driver()) {
		return 0;
	}

	cis = read_cis(cis_file, &size);
	if (!cis)
		return errno;

	rc = write_cis(cis, socket_no, size);
	free(cis);
	return rc;
}

static void usage(const char *progname) {
	fprintf(stderr,
		"Usage: %s [-r|--repair] <socketname>\n", progname);
	exit(1);
}

static struct option options[] = { { "repair", 0, NULL, 'r' },
				   { NULL, 0, NULL, 0 } };

int main(int argc, char **argv) {
	int ret;
	char *socket;
	unsigned int socket_no;
	const struct needs_cis * entry = NULL;
	tuple_t tuple;
	unsigned char buf[256];
	int opt;
	int repair = 0;

	while ((opt = getopt_long(argc, argv, "r", options, NULL)) != -1) {
		switch (opt) {
		case 'r':
			repair = 1;
			break;
		default:
			usage(argv[0]);
		}
	}
	if ((socket = getenv("SOCKET_NO"))) {
		socket_no = (unsigned int)strtoul(socket, NULL, 0);
	} else {
		if (argc < optind + 1)
			usage(argv[0]);
		socket_no = strtoul(argv[optind], NULL, 0);
	}

	ret = read_out_cis(socket_no, NULL);
	if (ret)
		return (ret);

	entry = &cis_table[0];

	while (entry) {
		if (!entry->cisfile)
			return 0;

		tuple.DesiredTuple = entry->code;
		tuple.Attributes = TUPLE_RETURN_COMMON;
		tuple.TupleData = buf;
		tuple.TupleDataMax = 255;
		pcmcia_get_first_tuple(BIND_FN_ALL, &tuple);

		tuple.TupleOffset = entry->ofs;

		pcmcia_get_tuple_data(&tuple);

		if (strncmp((char *) tuple.TupleData, entry->info,
			    strlen(entry->info)) != 0) {
			entry++;
			continue;
		}

		if (repair) {
			return repair_cis(entry->cisfile, socket_no);
		} else {
			printf("%s", entry->cisfile);
			return 1;
		}
	};

	return 0;
}
