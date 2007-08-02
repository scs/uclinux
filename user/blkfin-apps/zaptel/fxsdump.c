#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <math.h>
#include <netinet/in.h>

#ifdef STANDALONE_ZAPATA
#include "zaptel.h"
#else
#include <linux/zaptel.h>
#endif

#include "coeffs.h"

#define FREQ 1000.0
#define LEVEL 16384.0

#define FIRLEN (sizeof(coeffs) / sizeof(coeffs[0]))

int firguess(int sample)
{
	static float hist[FIRLEN] = { 0, };
	int x;
	float sum;
	for (x=FIRLEN-2;x>=0;x--)
		hist[x + 1] = hist[x];
	hist[0] = sample;
	sum = 0;
	for (x=0;x<FIRLEN;x++) {
		sum += hist[x] * (float)coeffs[x];
	}
	sum /= 32767.0;
	if (sum > 32767.0)
		sum = 32767.0;
	if (sum < -32768.0)
		sum = -32768.0;
	return (int)sum;
}

int obufnext(void)
{
	static int pos = 0;
	static int spos = 0;
	float res;
	if (++spos > 100) {
		res = LEVEL * sin(2.0 * FREQ * M_PI * (float)pos / 8000.0);
		if (res > 32767.0)
			res = 32767.0;
		if (res < -32768.0)
			res = -32768.0;
	
		pos++;
	} else {
		res = 0.0;
		spos++;
	}
	return (int)res;
}

int percent(int a, int b)
{
	float af = a;
	float bf = b;
	if (!b)
		return 0;
	return (int)((af/bf) * 100.0);
}

int main()
{
	int fd;
	int fdo,fdo2,fdo3;
	int res, x;
	int z=0;
	short ibuf[512];
	short obuf[512];
	short pred[512];
	fd = open("/dev/zap/zap1", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open: %s\n", strerror(errno));
		exit(1);
	}
	fdo = open("datain.raw", O_WRONLY | O_TRUNC | O_CREAT);
	fdo2 = open("dataout.raw", O_WRONLY | O_TRUNC | O_CREAT);
	fdo3 = open("datapred.raw", O_WRONLY | O_TRUNC | O_CREAT);
	x = 1;
#if 0
	if (ioctl(fd, ZT_AUDIOMODE, &x)) {
		fprintf(stderr, "audiomode: %s\n", strerror(errno));
		exit(1);
	}
	x = 1;
	if (ioctl(fd, ZT_SETLINEAR, &x)) {
		fprintf(stderr, "linear: %s\n", strerror(errno));
		exit(1);
	}
#endif
		for (x=0;x<sizeof(obuf)/sizeof(obuf[0]);x++) {
			obuf[x] = obufnext();
		}
	x = ZT_FLUSH_BOTH;
	if (ioctl(fd, ZT_FLUSH, &x)) {
		fprintf(stderr, "flush: %s\n", strerror(errno));
		exit(1);
	}
	for (;;) {
		for (x=0;x<sizeof(obuf) / sizeof(obuf[0]); x++)
			obuf[x] = htons(obuf[x]);
		res = write(fd, obuf, sizeof(obuf));
		if (res < sizeof(obuf)) {
			fprintf(stderr, "Write Buff: %d/%s\n", res, strerror(errno));
			exit(1);
		}
		res = read(fd, ibuf, sizeof(ibuf));
		if (res < sizeof(ibuf)) {
			fprintf(stderr, "Buff: %d/%s\n", res, strerror(errno));
			exit(1);
		}
		for (x=0;x<sizeof(ibuf) / sizeof(ibuf[0]); x++)
			ibuf[x] = ntohs(ibuf[x]);
		for (x=0;x<sizeof(obuf) / sizeof(obuf[0]); x++)
			obuf[x] = ntohs(obuf[x]);
		for (x=0;x<sizeof(pred) / sizeof(pred[0]); x++)
			pred[x] = firguess(obuf[x]);
		write(fdo, ibuf, sizeof(ibuf));
		write(fdo2, obuf, sizeof(obuf));
		write(fdo3, pred, sizeof(pred));
		for (x=0;x<sizeof(ibuf)/sizeof(ibuf[0]);x++) {
 			printf("(%5d/%5d/%5d) ", percent(ibuf[x], pred[x]) /*, (int)obuf[x] */, (int)ibuf[x], (int)pred[x]); 
			obuf[x] = obufnext();
			z++;
			if (z == 4) {
				printf("\n"); 
				z = 0;
			}
		}
	}
}
