/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / RC4
 * Copyright (c) 2002, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdio.h>
#include "common.h"
#include "rc4.h"

#define S_SWAP(a,b) do { u8 t = S[a]; S[a] = S[b]; S[b] = t; } while(0)

void rc4(u8 *buf, size_t len, u8 *key, size_t key_len)
{
	u8 S[256];
	u32 i, j, k;
	u8 kpos, *pos;

	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= key_len)
			kpos = 0;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data */
	pos = buf;
	i = j = 0;
	for (k = 0; k < len; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}
}
