/*
 * jit_in.c for dagrab
 *
 * This is filter for jitter correction inside the blocks of sectors
 * readed in one.
 *
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

#include <stdio.h>
#include <stdlib.h>

#include "dagrab.h"
#include "print.h"
#include "const.h"

#define SSIZE 4		/* sample size */

void jitter_in(register char *pp, int length, int opt_delta)
{
	signed short m, l, r, h, hr, hl, hll, which;
	register char *p;
	int i;

	/* which: left and right channel */
	for (which = 3; which > 0; which -= 2)
		for (p = pp + which + 2 * SSIZE;
		     (p - pp) < length - 2 * SSIZE;
		     p += SSIZE) {
			m = *p;	/* tested byte (medium) */
			l = *(p - SSIZE);	/* prev. before tested (left) */
			r = *(p + SSIZE);	/* next after tested (right) */

			h = abs(hr = m - r);	/* right delta */
			if (h <= opt_delta)	/* is it not jittered? */
				continue;	/* this byte seems to be ok, go to next */

			h = abs(hl = l - m);	/* left delta ... */
			if (h <= opt_delta)
				continue;

			/* is tested value between prev. (left) and next (right)? */
			if ((l < m && m < r) || (r < m && m < l))
				continue;

			for (i = -2 * SSIZE; i; i += SSIZE) {
				hll =
				    *(p + i) - *(p + i + 3 * SSIZE);

				if (hll > 0)
					if ((hr > 0 && hr < hll) ||
					    (hl > 0 && hl < hll))
						goto is_ok;
				if (hll < 0)
					if ((hr < 0 && hr > hll) ||
					    (hl < 0 && hl > hll))
						goto is_ok;
			}
			/*
			 * the "broken" byte is aproximated as an average of
			 * left and right byte; i'm so lazy to look to the
			 * lower byte of 16bit values
			 */
			*p = (*(p + SSIZE) + *(p - SSIZE)) / 2;
			view_status(ID_JITTER, NULL);
		      is_ok:	/* means continue */
			;
		}
}
