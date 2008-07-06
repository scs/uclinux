/*
 *    Description:  FPGA Converter Card test Application
 *
 *   Copyright (C) 2008 Michael Hennerich <hennerich@blackfin.uclinux.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 ***************************************************************************/

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <math_const.h>

#include "parse.h"

#define PPI_DEVICE      "/dev/ppi"
#define VERSION         "0.1"

#define SAMPLES  4096
#define BUFFERSIZE (SAMPLES * 2)

void usage(FILE * fp, int rc)
{
	fprintf(fp,
		"Usage: fpga_test [-h?v] [-r -c N] [-f frequency] [-d dacfile] \n");
	fprintf(fp, "        -r             Read Samples to file\n");
	fprintf(fp, "        -c N           Read Samples to file N times\n");
	fprintf(fp, "        -f             Number of periodes per record\n");
	fprintf(fp, "        -d dacfile     use dacfile\n");
	fprintf(fp, "        -h?            this help\n");
	fprintf(fp, "        -v             print version info\n");
	exit(rc);
}

int make_outfile(char *fname, unsigned short *samples, int cnt)
{
	int i;
	/* open file for write */
	FILE *pFile_init;

	pFile_init = fopen (fname, "w");

	if (pFile_init < 0) {
		perror("open");
		return errno;
	}

	/* print information */
	for (i = 0; i< cnt;i++)
		fprintf (pFile_init, "%d\n", samples[i]);

	fclose (pFile_init);
	return 0;
};

int main(int argc, char *argv[])
{

	int fd, i, c;
	unsigned short *buffer;
	int r = 0, f = 0, cnt = 1, d = 0;
	char dacfile[50];
	char adcfile[50];
	while ((c = getopt(argc, argv, "vth?trf:c:b:d:")) > 0) {
		switch (c) {
		case 'v':
			printf("%s: version %s\n", argv[0], VERSION);
			exit(0);
		case 'r':
			r++;
			break;
		case 'f':
			f = atoi(optarg);
			break;
		case 'd':
			d++;
			strcpy(dacfile, optarg);
			break;
		case 'c':
			r++;
			cnt = atoi(optarg);
			break;
		case 'h':
		case '?':
			usage(stdout, 0);
			break;

		default:
			fprintf(stderr, "ERROR: unkown option '%c'\n", c);
			usage(stderr, 1);
			break;
		}
	}


	/* Open /dev/ppi */
	fd = open(PPI_DEVICE, O_RDWR, 0);
	if (fd == -1) {
		printf("Could not open dev ppi : %d \n", errno);
		exit(1);
	}

	buffer = malloc(BUFFERSIZE);

	if(buffer == NULL) {
		perror("malloc");
		close(fd);
	}

	if (f || d) {
		if (d) {
			/* Read DAC sequence from file */
			read_config(dacfile, buffer);
		} else {
			/* Generate Sinewave with frequency f */
			for(i = 0; i < SAMPLES; i++)
				buffer[i] = (unsigned short) (2048 + (2047 * sin(f * 2 * PI * i / SAMPLES)));
		}

		/* Write DAC sequence into FPGA */
		write(fd, buffer, BUFFERSIZE);
	}

	if (r) {
		/* Read count c times ADC buffer from FPGA and save to files */
		while (cnt--) {
				read(fd, buffer, BUFFERSIZE);
				sprintf(adcfile, "out_%d.csv", cnt);
				make_outfile(adcfile, buffer, SAMPLES);
		}
	}

	close(fd);
	free(buffer);
	exit(0);
}
