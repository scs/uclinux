/*
 * jitter.c for dagrab
 *
 * This is for jitter correction when joining blocks of sectors.
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

#include <string.h>
#ifdef DEBUG
#include <stdio.h>
#endif
#include "dagrab.h"
#include "const.h"
#include "print.h"

/* For the begining of the track. Try to guess from the deviation of
   higher and lower bytes if it is 1 byte shifted */
int need_1B_shift(Buffer * b, int trk_pos)
{
	signed int i;
	double koef = 3.5, avg[2] = { 0.0, 0.0 }, sq[2] = { 0.0, 0.0 };

	for (i = b->size - 2; i >= 0; i -= 2) {
		avg[0] += (signed char) b->buffer[i + 1];
		avg[1] += (signed char) b->buffer[i];
	}
	avg[0] /= b->size / 2;
	avg[1] /= b->size / 2;

	for (i = b->size - 2; i >= 0; i -= 2) {
		double tmp;

		tmp = (((signed char) b->buffer[i + 1]) - avg[0]);
		sq[0] += tmp * tmp;

		tmp = (((signed char) b->buffer[i]) - avg[1]);
		sq[1] += tmp * tmp;
	}
#ifdef DEBUG
	if (opt_debug) 
		printf("1B shift: %5.3e (NO) <? %5.3e [%7i B]\n" "need 1B shift: ", 
			sq[0], sq[1], b->size);
#endif
	if (trk_pos == TRK_END)
		koef = 0;

	/************** if sq[1] > sq[0], it's probably OK ************/
	if (sq[0] > sq[1] + koef * b->size) {
#ifdef DEBUG
		if (opt_debug)
			puts("YES\n");
#endif
		return YES;
	}
	if (sq[1] > sq[0] + koef * b->size) {
#ifdef DEBUG
		if (opt_debug)
			puts("NO\n");
#endif
		return NO;
	}
#ifdef DEBUG
	if (opt_debug)
		puts("DONTKNOW\n");
#endif
	return DONTKNOW;
}

char *str_str(char *orig, int origsize, char *needle, int nsize)
{
	int j, n;
	unsigned char mistakes;
	char *found = orig;

	if (opt_jitter_in)
		nsize -= 8;

	n = nsize - 1;
	for (; found - orig + nsize < origsize;) {
		mistakes = 0;
		found = memchr(found, *needle, origsize - (found - orig));
		/* We could use memstr, but we allow mistake in key: */
		if (found) {
			for (j = n/* nsize - 1*/; j; j--)
				if (*(found + j) != *(needle + j))
					if (mistakes++ > 1)
						break;
			if (!j && found < orig + origsize - nsize)
				return found;
			found++;
		} else
			break;
	}
	return NULL;
}

int jitter(Buffer * buf_act, char *ending, int retry)
{
	int l, keysize = KEYLEN * sizeof(int), step;
	char *found_it;

	if (opt_dumb) 
		return 0;

	/* Find "ending"  */
	found_it =
	    str_str(buf_act->buffer, buf_act->size, ending, keysize);

	/* Compute shift */
	l = (found_it - buf_act->buffer);

	step = 1 + 0.05 * opt_blocks;

	if (!found_it) {
		static int overlap_before;

		view_status(ID_OVERLAP, &(V_STAT[OVERLAP_ERR]));

		if (!retry)
			overlap_before = overlap;

		/* last tries to go to other side */
		if (retry >= RETRYS_O - 1) {
			if (retry == RETRYS_O - 1)
				overlap = overlap_before;
			overlap -= 3 * step;
			view_status(ID_OVERLAP, &overlap);
			return -1;
		}
		if (!(retry % 2)) {
			overlap += step;
			if (overlap >= opt_blocks)
				overlap = opt_blocks / 2;
			view_status(ID_OVERLAP, &overlap);
		}
		return -1;
	}
	return l;
}
