/*
 * File:         fpga_loader.c
 * Based on:
 * Description:  Slave Serial Mode configuration/bootload utility for Xilinx FPGAs
 *
 * Michael Hennerich Copyright 2008 Analog Devices Inc.
 *
 * Licensed under the GPL-2 or later
 *
 * This utility program requires following Linux device drivers installed on your system:
 *
 * spidev.c --
 * simple synchronous userspace interface to SPI devices
 * by Andrea Paterniani and David Brownell
 *
 * simple-gpio.c --
 * Simple character interface to GPIOs by Mike Frysinger.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/types.h>
#include <linux/spi/spidev.h>

#define TIMEOUT 2

static char copybuf[4096];

int copy(FILE *read_f, int fd)
{
	int n;
	int wrote;

	alarm(TIMEOUT);
	while (n = fread(copybuf, 1, sizeof(copybuf), read_f)) {
		alarm(TIMEOUT);
		printf(".");
		fflush(stdout);
		wrote = write(fd, copybuf, n);
		alarm(TIMEOUT);
		if (wrote < 1)
			return (-1);
	}
	alarm(0);
	return 0;
}

int transfer(int fd, char *name)
{
	FILE *infile;

	if (!(infile = fopen(name, "r"))) {
		alarm(TIMEOUT);
		fprintf(stderr, "Unable to open file %s, %d\n", name, errno);
		alarm(0);
		return -1;
	}

	copy(infile, fd);
	fclose(infile);

	return 0;
}

static void dumpstat(const char *name, int fd)
{
	__u8 mode, lsb, bits;
	__u32 speed;

	if (ioctl(fd, SPI_IOC_RD_MODE, &mode) < 0) {
		perror("SPI rd_mode");
		return;
	}
	if (ioctl(fd, SPI_IOC_RD_LSB_FIRST, &lsb) < 0) {
		perror("SPI rd_lsb_fist");
		return;
	}
	if (ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits) < 0) {
		perror("SPI bits_per_word");
		return;
	}
	if (ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed) < 0) {
		perror("SPI max_speed_hz");
		return;
	}

	printf("%s: spi mode %d, %d bits %sper word, %d Hz max\n",
	       name, mode, bits, lsb ? "(lsb first) " : "", speed);
}

int main(int argc, char **argv)
{
	int c, v = 0;
	int fd, fd_done, fd_int_b, fd_prog_b;
	char *name;
	char *spidev = DEFAULT_SPIDEV;
	char byte[2], mode = SPI_MODE_2;

	while ((c = getopt(argc, argv, "hm:d:v")) != EOF) {
		switch (c) {
		case 'd':
			spidev = optarg;
			continue;
		case 'm':
			mode = atoi(optarg);
			continue;
		case 'v':
			v++;
			break;
		case 'h':
		case '?':
		      usage:
			fprintf(stderr,
				"usage: %s [-hv] [-d /dev/spidevB.D] [-m SPI_MODE] infile\n",
				argv[0]);
			return 1;
		}
	}

	if ((optind + 1) != argc)
		goto usage;
	name = argv[optind];

	if (v) {
		printf("Config File\t\t: %s\n", name);
		printf("SPI device\t\t: %s\n", spidev);
	}

	fd = open(spidev, O_RDWR);
	if (fd < 0) {
		perror(spidev);
		return errno;
	}

	ioctl(fd, SPI_IOC_WR_MODE, &mode);

	fd_done = open(DEFAULT_DONE, O_RDWR);
	if (fd_done < 0) {
		perror(DEFAULT_DONE);
		return errno;
	}

	fd_int_b = open(DEFAULT_INT_B, O_RDWR);
	if (fd_int_b < 0) {
		perror(DEFAULT_INT_B);
		return errno;
	}

	fd_prog_b = open(DEFAULT_PROG_B, O_RDWR);
	if (fd_prog_b < 0) {
		perror(DEFAULT_PROG_B);
		return errno;
	}

	dumpstat(spidev, fd);

	write(fd_int_b, "I", 1);
	write(fd_done, "I", 1);

	/*
	 * PROG_B should never be driven high by Blackfin.
	 * Simulate open drain output. Configure as input
	 * for HI and drive 0 for LOW.
	 */

	write(fd_prog_b, "O0", 2);

	/*
	 * Pulse PROG_B to initiate configuration sequence
	 */

	usleep(1);
	write(fd_prog_b, "I", 1);
	close(fd_prog_b);

	if (v)
		printf("Waiting INT_B -> HIGH\n");

	alarm(TIMEOUT);

	/*
	 * Monitor INIT_B pin goes High,
	 * indicating that the FPGA is ready to receive its first data.
	 */

	while (1) {
		if (read(fd_int_b, byte, 1) != 1)
			perror("unable to read device");

		if (byte[0] == '1')
			break;
		usleep(10);
	}

	close(fd_int_b);

	transfer(fd, name); /* Send FPGA bitfile by SPI */

	alarm(TIMEOUT);

	/*
	 * Continue supplying data and clock signals
	 * until either the DONE pin goes High, indicating a successful
	 * configuration, or until the INIT_B pin goes Low, indicating a
	 * configuration error.
	 */

	if (v)
		printf("\nWaiting CONFIG DONE\n");

	while (1) {
		if (read(fd_done, byte, 1) != 1)
			perror("unable to read device");

		if (byte[0] == '1')
			break;
		/*
		 * The configuration process requires
		 * more clock cycles than indicated from the configuration file
		 * size. Additional clocks are required during the FPGA's
		 * start-up sequence.
		 */

		write(fd, copybuf, sizeof(copybuf));
	}

	close(fd);
	close(fd_done);

	alarm(0);

	if (v)
		printf(" DONE!\n");
	else
		printf("\n");

	return 0;
}
