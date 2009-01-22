/****************************************************************************** 
 * Filename:	sport_test.c - test sport driver
 * Description:	This program write data to ad73311 audio card through
 * 		 interface /dev/sport.
 * Author:	Roy Huang <roy.huang@analog.com>
 */

#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "bfin_sport.h"
#include "ad73311.h"

#define SPORT "/dev/sport0"

int transmit = 1;
int omode = O_RDWR;
int sport = 0;
int count = 10 * 2 * 8000; /* Only record 10 second */

/* Definitions for Microsoft WAVE format */
#define RIFF		0x46464952
#define WAVE		0x45564157
#define FMT		0x20746D66
#define DATA		0x61746164
#define PCM_CODE	1
#define WAVE_MONO	1
#define WAVE_STEREO	2

struct wave_header {
	u_long	main_chunk;	/* 'RIFF' */
	u_long	length;		/* filelen */
	u_long	chunk_type;	/* 'WAVE' */

	u_long	sub_chunk;	/* 'fmt ' */
	u_long	sc_len;		/* length of sub_chunk, =16 */
	u_short	format;		/* should be 1 for PCM-code */
	u_short	modus;		/* 1 Mono, 2 Stereo */
	u_long	sample_fq;	/* frequence of sample */
	u_long	byte_p_sec;
	u_short	byte_p_spl;	/* samplesize; 1 or 2 bytes */
	u_short	bit_p_spl;	/* 8, 12 or 16 bit */ 

	u_long	data_chunk;	/* 'data' */
	u_long	data_length;	/* samplecount */
};

int test_wavefile (void *buffer)
{
	struct wave_header *wp = buffer;
	if (wp->main_chunk == RIFF && wp->chunk_type == WAVE &&
			wp->sub_chunk == FMT && wp->data_chunk == DATA) {
		if (wp->format != PCM_CODE) {
			fprintf (stderr, "Can't play non-pcm-coded wave\n");
			return -1;
		}

		if (wp->modus != WAVE_MONO) {
			fprintf (stderr, "Can only play mono wave file\n");
			return -1;
		}
	}
	return 0;
}

#define BUF_LEN		0x1000

static void fill_waveheader(int fd, int cnt)
{
	struct wave_header wh;

	wh.main_chunk = RIFF;
	wh.length     = cnt + sizeof(wh) - 8; 
	wh.chunk_type = WAVE;
	wh.sub_chunk  = FMT;
	wh.sc_len     = 16;
	wh.format     = PCM_CODE;
	wh.modus      =  1;
	wh.sample_fq  = 8000;
	wh.byte_p_spl = 2;
	wh.byte_p_sec = 8000 * 1 * 2;
	wh.bit_p_spl  = 16;
	wh.data_chunk = DATA;
	wh.data_length= cnt;
	write (fd, &wh, sizeof(wh));
}

int main (int argc, char *argv[])
{
	int fd;
	char *filename, c;
        char *button="/dev/gpio4";
        FILE *fp;
	unsigned short ctrl_regs[6];
	struct sport_config config;
	unsigned char *buffer = NULL;

	if (argc < 3) {
		fprintf (stderr, "Usage: sport_test -r or -t filename\n");
		return -1;
	}

	while ((c = getopt (argc, argv, "rt")) != EOF)
		switch (c) {
		case 'r':
			transmit = 0;
			break;
		case 't':
			transmit = 1;
			break;
		default:
			fprintf (stderr, "Usage: sport_test -r or -t filename\n");
			exit (-1);
		}

	filename = argv[optind];

	sport = open (SPORT, omode, 0);
	if (sport < 0) {
		fprintf (stderr, "Failed to open " SPORT);
		exit (-1);
	}

	if ((buffer = malloc(BUF_LEN))  == NULL) {
		perror ("Failed to allocate memory\n");
		close (sport);
		return -1;
	}

	if (transmit == 1) { /* Test and read wave data file */
		if ( (fd = open (filename, O_RDONLY, 0)) < 0) {
			perror (filename);
			close (sport);
			return -1;
		}
		if (read (fd, buffer, sizeof(struct wave_header)) < 0) {
			perror(filename);
			close(sport);
			free(buffer);
			return -1;
		}
		if (test_wavefile(buffer) < 0) {
			close(sport);
			free(buffer);
			return -1;
		}
	} else {
		/* Open the file for write data */
		if ( (fd = open (filename, O_WRONLY | O_CREAT , O_TRUNC)) <0) {
			fprintf(stderr, "Failed to open %s\n", filename);
			close (sport);
			return -1;
		}
		/* Write the head of the wave file */
		fill_waveheader(fd, count);
	}
  
        fp = fopen(button, "w+");
        if (!fp)
                printf("unable to open specified device '%s'", button);
       /* set it to Output mode */
        if (fwrite("O", 1, 1, fp) != 1)
                printf("unable to set to output mode");
        if (fwrite("1", 1, 1, fp) != 1)
                printf("unable to set to 1 value");


	/* IOCTL to enable ad73311 
	if (ioctl (sport, ENABLE_AD73311, 1) < 0) {
		fprintf(stderr, "failed to enable ad73311 \n");
		close (sport);
		return -1;
	}
	*/
         fclose(fp);

	/* Set registers on AD73311L through SPORT.  */
#if 0
	/* DMCLK = MCLK/4 = 16.384/4 = 4.096 MHz
	 * SCLK = DMCLK/8 = 512 KHz
	 * Sample Rate = DMCLK/512 = 8 KHz */
	ctrl_regs[0] = AD_CONTROL | AD_WRITE | CTRL_REG_B | MCDIV(0x3) | \
								DIRATE(0x2) ;
#else
	/* DMCLK = MCLK = 16.384 MHz
	 * SCLK = DMCLK/8 = 2.048 MHz
	 * Sample Rate = DMCLK/2048  = 8 KHz */
	ctrl_regs[0] = AD_CONTROL | AD_WRITE | CTRL_REG_B | MCDIV(0) | \
							SCDIV(0) | DIRATE(0);

#endif
	ctrl_regs[1] = AD_CONTROL | AD_WRITE | CTRL_REG_C | PUDEV | PUADC | \
				PUDAC | PUREF | REFUSE ;/* Register C */
	ctrl_regs[2] = AD_CONTROL | AD_WRITE | CTRL_REG_D | OGS(0) | IGS(5);
	ctrl_regs[3] = AD_CONTROL | AD_WRITE | CTRL_REG_E | DA(0x1f);
	ctrl_regs[4] = AD_CONTROL | AD_WRITE | CTRL_REG_F | SEEN ;
//	ctrl_regs[4] = AD_CONTROL | AD_WRITE | CTRL_REG_F | ALB;
//	ctrl_regs[4] = AD_CONTROL | AD_WRITE | CTRL_REG_F | 0;
	/* Put AD73311L to data mode */
	ctrl_regs[5] = AD_CONTROL | AD_WRITE | CTRL_REG_A | MODE_DATA;
//	ctrl_regs[5] = AD_CONTROL | AD_WRITE | CTRL_REG_A | SLB | MODE_DATA;

#if 0
	fprintf(stderr, "0x%04x 0x%04x 0x%04x 0x%04x 0x%4x 0x%4x\n",
			ctrl_regs[0], ctrl_regs[1], ctrl_regs[2],
			ctrl_regs[3], ctrl_regs[4], ctrl_regs[5]);
#endif

	memset(&config, 0, sizeof (struct sport_config));
	config.fsync = 1;
	config.word_len = 16;
	config.dma_enabled = 1;

	/* Configure sport controller by ioctl */
	if (ioctl (sport, SPORT_IOC_CONFIG, &config) < 0) {
		fprintf(stderr, "failed to config sport\n");
		free(buffer);
		close(sport);
		close(fd);
		return -1;
	}
	/* Write control data to ad73311's control register by write operation*/
	if (write (sport, (char*)ctrl_regs, 12) < 0) {
		perror("Failed write ctrl regs\n");
		free(buffer);
		close(sport);
		close(fd);
		return -1;
	}

	if (transmit == 1)
		/* Write data into sport device through write operation */
		while (read(fd, buffer, BUF_LEN) > 0 ) {
			if (write (sport, buffer, BUF_LEN) != BUF_LEN) {
				perror (SPORT);
				free(buffer);
				close(sport);
				close(fd);
				return -1;
			}
		}
	else {
		int left = count, temp1, temp2;
		/* Read data from sport and write it into file */
		while (left > 0) {
			temp1 = left > BUF_LEN? BUF_LEN: left;
			if ((temp2 = read (sport, buffer, temp1))<0) {
				perror (SPORT);
				free(buffer);
				close(sport);
				close(fd);
				return -1;
			}
			write(fd, buffer, temp1);
			left -= temp2;
		}
	}

	/* IOCTL to disable ad73311 */
	ioctl (sport, ENABLE_AD73311, 0);

	close (sport);
	close (fd);
	free(buffer);

	return 0;
}
