/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / common helper functions, etc.
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdio.h>
#include "common.h"


int hostapd_get_rand(u8 *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "r");
	if (f == NULL) {
		printf("Could not open /dev/urandom.\n");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	fclose(f);

	return rc != len ? -1 : 0;
}


void hostapd_hexdump(const char *title, u8 *buf, size_t len)
{
	size_t i;
	printf("%s - hexdump(len=%d):", title, len);
	for (i = 0; i < len; i++)
		printf(" %02x", buf[i]);
	printf("\n");
}


static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int hwaddr_aton(char *txt, u8 *addr)
{
	int i;

	for (i = 0; i < 6; i++) {
		int a, b;

		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}

	return 0;
}
