/*
 * main.h for dagrab
 */

#ifndef _MAIN_H
#define _MAIN_H 1

#define TRUE		1
#define FALSE		0

typedef unsigned short Word;

typedef struct {
	int min;
	int max;
	int *starts;
	char *types;
	char *cddb;		/* complete cddb entry */
	int cddb_size;
	char *gnr;		/* category; NULL if not obtained via cddbp */
} cd_trk_list;

typedef struct {
	char Rid[4];
	unsigned Rlen;		/* 0x24+Dlen */
	char Wid[4];
	char Fid[4];
	unsigned Flen;
	Word tag;
	Word channel;
	unsigned sample_rate;
	unsigned byte_rate;
	Word align;
	Word sample;
	char Did[4];
	unsigned Dlen;
} Wavefile;

typedef struct {
	char *kw;
	int idx;
	char *desc;
	char *printout;
} kword;

#define KW_TRACK	6
#define KW_FULLD	5
#define KW_AUTHOR	4
#define KW_NUM		3
#define KW_DISK		2
#define KW_GNR		1
#define KW_YEAR		0
#define KW_MAX		6

#endif				/* _MAIN_H */
