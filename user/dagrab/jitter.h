/*
 * jitter.h for dagrab
 */

#ifndef _JITTER_H
#define _JITTER_H 1

int need_1B_shift(Buffer * b, int trk_pos);
int jitter(Buffer * p1, char *p2, int retry);

#endif				/* _JITTER_H */
