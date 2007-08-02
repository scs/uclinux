/*
 * Monitor a Zaptel Channel
 *
 * Written by Mark Spencer <markster@linux-support.net>
 * Based on previous works, designs, and architectures conceived and
 * written by Jim Dixon <jim@lambdatel.com>.
 *
 * Copyright (C) 2001 Jim Dixon / Zapata Telephony.
 * Copyright (C) 2001 Linux Support Services, Inc.
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under thet erms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 * Primary Author: Mark Spencer <markster@linux-support.net>
 *
 */

#include <stdio.h> 
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#ifdef STANDALONE_ZAPATA
#include "zaptel.h"
#include "tonezone.h"
#else
#include <linux/zaptel.h>
#include <tonezone.h>
#endif
#include <linux/soundcard.h>

#define BUFFERS 4

#define FRAG_SIZE 8

/* Put the ofh (output file handle) outside
 * the main loop in case we ever add a signal
 * hanlder.
 */
static FILE*  ofh = 0;

static int stereo = 0;
int audio_open(void)
{
	int fd;
	int speed = 8000;
	int fmt = AFMT_S16_LE;
	int fragsize = (BUFFERS << 16) | (FRAG_SIZE);
	struct audio_buf_info ispace, ospace;
	fd = open("/dev/dsp", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to open /dev/dsp: %s\n", strerror(errno));
		return -1;
	}
	/* Step 1: Signed linear */
	if (ioctl(fd, SNDCTL_DSP_SETFMT, &fmt) < 0) {
		fprintf(stderr, "ioctl(SETFMT) failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	/* Step 2: Make non-stereo */
	if (ioctl(fd, SNDCTL_DSP_STEREO, &stereo) < 0) {
		fprintf(stderr, "ioctl(STEREO) failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (stereo != 0) {
		fprintf(stderr, "Can't turn stereo off :(\n");
	}
	/* Step 3: Make 8000 Hz */
	if (ioctl(fd, SNDCTL_DSP_SPEED, &speed) < 0) {
		fprintf(stderr, "ioctl(SPEED) failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (speed != 8000) 
		fprintf(stderr, "Warning: Requested 8000 Hz, got %d\n", speed);
	if (ioctl(fd, SNDCTL_DSP_SETFRAGMENT, &fragsize)) {
		fprintf(stderr, "Sound card won't let me set fragment size to 10 64-byte buffers (%x)\n"
						"so sound may be choppy: %s.\n", fragsize, strerror(errno));
	}	
	bzero(&ispace, sizeof(ispace));
	bzero(&ospace, sizeof(ospace));

	if (ioctl(fd, SNDCTL_DSP_GETISPACE, &ispace)) {
		/* They don't support block size stuff, so just return but notify the user */
		fprintf(stderr, "Sound card won't let me know the input buffering...\n");
	}
	if (ioctl(fd, SNDCTL_DSP_GETOSPACE, &ospace)) {
		/* They don't support block size stuff, so just return but notify the user */
		fprintf(stderr, "Sound card won't let me know the output buffering...\n");
	}
	fprintf(stderr, "New input space:  %d of %d %d byte fragments (%d bytes left)\n", 
		ispace.fragments, ispace.fragstotal, ispace.fragsize, ispace.bytes);
	fprintf(stderr, "New output space:  %d of %d %d byte fragments (%d bytes left)\n", 
		ospace.fragments, ospace.fragstotal, ospace.fragsize, ospace.bytes);
	return fd;
}

int pseudo_open(void)
{
	int fd;
	int x = 1;
	fd = open("/dev/zap/zappseudo", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Unable to open pseudo channel: %s\n", strerror(errno));
		return -1;
	}
	if (ioctl(fd, ZT_SETLINEAR, &x)) {
		fprintf(stderr, "Unable to set linear mode: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	x = 240;
	if (ioctl(fd, ZT_SET_BLOCKSIZE, &x)) {
		fprintf(stderr, "unable to set sane block size: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

#define barlen 35
#define baroptimal 3250
//define barlevel 200
#define barlevel ((baroptimal/barlen)*2)
#define maxlevel (barlen*barlevel)

void draw_barheader()
{
	char bar[barlen+5];

	memset(bar, '-', sizeof(bar));
	memset(bar, '<', 1);
	memset(bar+barlen+2, '>', 1);
	memset(bar+barlen+3, '\0', 1);

	strncpy(bar+(barlen/2), "(RX)", 4);
	printf("%s", bar);

	strncpy(bar+(barlen/2), "(TX)", 4);
	printf(" %s\n", bar);
}

void draw_bar(int avg, int max)
{
	char bar[barlen+5];

	memset(bar, ' ', sizeof(bar));

	max /= barlevel;
	avg /= barlevel;
	if (avg > barlen)
		avg = barlen;
	if (max > barlen)
		max = barlen;
	
	if (avg > 0) 
		memset(bar, '#', avg);
	if (max > 0) 
		memset(bar + max, '*', 1);

	bar[barlen+1] = '\0';
	printf("%s", bar);
	fflush(stdout);
}

void visualize(short *tx, short *rx, int cnt)
{
	int x;
	float txavg = 0;
	float rxavg = 0;
	static int txmax = 0;
	static int rxmax = 0;
	static int sametxmax = 0;
	static int samerxmax = 0;
	static int txbest = 0;
	static int rxbest = 0;
	float ms;
	static struct timeval last;
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	ms = (tv.tv_sec - last.tv_sec) * 1000.0 + (tv.tv_usec - last.tv_usec) / 1000.0;
	for (x=0;x<cnt;x++) {
		txavg += abs(tx[x]);
		rxavg += abs(rx[x]);
	}
	txavg = abs(txavg / cnt);
	rxavg = abs(rxavg / cnt);
	
	if (txavg > txbest)
		txbest = txavg;
	if (rxavg > rxbest)
		rxbest = rxavg;
	
	/* Update no more than 10 times a second */
	if (ms < 100)
		return;
	
	/* Save as max levels, if greater */
	if (txbest > txmax) {
		txmax = txbest;
		sametxmax = 0;
	}
	if (rxbest > rxmax) {
		rxmax = rxbest;
		samerxmax = 0;
	}

	memcpy(&last, &tv, sizeof(last));

	/* Clear screen */
	printf("\r ");
	draw_bar(rxbest, rxmax);
	printf("   ");
	draw_bar(txbest, txmax);
	txbest = 0;
	rxbest = 0;
	
	/* If we have had the same max hits for x times, clear the values */
	sametxmax++;
	samerxmax++;
	if (sametxmax > 6) {
		txmax = 0;
		sametxmax = 0;
	}
	if (samerxmax > 6) {
		rxmax = 0;
		samerxmax = 0;
	}
}

int main(int argc, char *argv[])
{
	int afd = -1, pfd, pfd2 = -1;
	short buf[8192];
	short buf2[16384];
	char  output_file[255];
	int res, res2;
	int visual = 0;
	int x,i;
	struct zt_confinfo zc;

	if ((argc < 2) || (atoi(argv[1]) < 1)) {
		fprintf(stderr, "Usage: ztmonitor <channel num> [-v] [-f FILE]\n");
		exit(1);
	}
	for (i = 2; i < argc; ++i) {
		if (!strcmp(argv[i], "-v"))
		        visual = 1;
       		else if (!strcmp(argv[i], "-f") && (i+1) < argc) {
			++i; /*we care about hte file name */
			if (strlen(argv[i]) < 255 ) {
				strcpy(output_file, argv[i]);
				fprintf(stderr, "Output to %s\n", output_file);
				if ((ofh = fopen(output_file, "w"))<0) {
					fprintf(stderr, "Could not open %s for writing: %s\n", output_file, strerror(errno));
					exit(0);
				}
				fprintf(stderr, "Run e.g., 'sox -r 8000 -s -w -c 1 file.raw file.wav' to convert.\n");
			} else {
				fprintf(stderr, "File Name %s too long\n",argv[i+1]);
			}
		}
	}
	if (!visual) {
		/* Open audio */
		if ((afd = audio_open()) < 0) {
			printf("Cannot open audio ...\n");
			if (!ofh) exit(0);
		}
	}
	/* Open Pseudo device */
	if ((pfd = pseudo_open()) < 0)
		exit(1);
	if (visual && ((pfd2 = pseudo_open()) < 0))
		exit(1);
	/* Conference them */
	memset(&zc, 0, sizeof(zc));
	zc.chan = 0;
	zc.confno = atoi(argv[1]);
	if (visual) {
		/* Two pseudo's, one for tx, one for rx */
		zc.confmode = ZT_CONF_MONITORTX;
		if (ioctl(pfd, ZT_SETCONF, &zc) < 0) {
			fprintf(stderr, "Unable to monitor: %s\n", strerror(errno));
			exit(1);
		}
		memset(&zc, 0, sizeof(zc));
		zc.chan = 0;
		zc.confno = atoi(argv[1]);
		zc.confmode = ZT_CONF_MONITOR;
		if (ioctl(pfd2, ZT_SETCONF, &zc) < 0) {
			fprintf(stderr, "Unable to monitor: %s\n", strerror(errno));
			exit(1);
		}
	} else {
		zc.confmode = ZT_CONF_MONITORBOTH;
		if (ioctl(pfd, ZT_SETCONF, &zc) < 0) {
			fprintf(stderr, "Unable to monitor: %s\n", strerror(errno));
			exit(1);
		}
	}
	if (visual) {
		printf("\nVisual Audio Levels.\n");
		printf("--------------------\n");
		printf(" Use zapata.conf file to adjust the gains if needed.\n\n");
		printf("( # = Audio Level  * = Max Audio Hit )\n");
		draw_barheader();
	}
	/* Now, copy from pseudo to audio */
	for (;;) {
		res = read(pfd, buf, sizeof(buf));
		if (res < 1) 
			break;
		if (visual) {
			res2 = read(pfd2, buf2, res);
			if (res2 < 1) 
				break;
			if (res == res2)
				visualize((short *)buf, (short *)buf2, res/2);
			else
				printf("Huh?  res = %d, res2 = %d?\n", res, res2);
			
		} else {
			if (ofh)	        
				fwrite(buf, 1, res, ofh);
		 	if (afd) {
				if (stereo) {
					for (x=0;x<res;x++)
						buf2[x<<1] = buf2[(x<<1) + 1] = buf[x];
					write(afd, buf2, res << 1);
				} else
					write(afd, buf, res);
			}
		}
	}
	if (ofh) fclose(ofh); /*Never Reached */
	exit(0);
}
