/*
 * const.h for dagrab
 */

#ifndef _CONST_H
#define _CONST_H 1

/* 
 * you can edit those values (see dagrab --longhelp or manpage): 
 */
#define CDDEVICE	"/dev/cdrom"
#define MAX_SPEED	64	/* maximum speed of your drive */

#define N_BUF		8	/* -n */
#define RETRYS		4	/* Retrys when it can't read */
#define RETRYS_O	15	/* Retrys when overlap errors occure */
#define DELTA		24	/* implicit -j */
#define BLEN		1024	/* length in chars of command/trackname */
#define OVERLAP		1	/* minimum number of sectors for overlapping */

#define CDDB_PORT	888
#define CDDB_PATH	"/usr/lib/X11/xmcd/cddb"
#define CDDB_HOST	"de.freedb.org"
#define CDDB_MAX	65535

#define KEYLEN		16	/* number of samples for overlap checking */

/* 
 * do not edit lines below: 
 */
#define IFRAMESIZE	(CD_FRAMESIZE_RAW/sizeof(int))

#define OVERLAP_ERR	0	/* see print.c */
#define OVERLAP_OK	1
#define NUL 		2

#define	ID_BLOCKS	0
#define ID_SPEED	1
#define ID_BADDATA	2
#define ID_OVERLAP	3
#define ID_SECTORS	4
#define ID_MISSING	7
#define ID_PERC		8
#define ID_REALSPEED	9
#define ID_NULL		10
#define ID_JITTER	11

#define LEFT		1
#define RIGHT		3

#define SHORTHELP	1
#define LONGHELP	2

#define OK		0
#define KO		1

#define	TRK_BEGIN	0
#define TRK_INSIDE	1
#define TRK_END		2

#define NO		0
#define YES		1

#define MAIN 0
#define THREAD 1

#define DONTKNOW	2
#define YES_AND_FREE_IT	2

typedef struct {
	int size;
	char *buffer;	/* buffer can be changed */
	char *orig;	/* orig remembers where to free() */
} Buffer;

#endif				/* _CONST_H */
