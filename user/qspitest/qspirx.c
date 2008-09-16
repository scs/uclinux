/*
 * qspirx.c
 *
 * A small testbed for receiving data from an MCP3202 device (a small
 * two-channel ADC) on the qspi bus of a Motorola Coldfire 5272 using
 * the mcf_qspi kernel driver.
 *
 * It is based on kendin-config.c, whose copyright appears below,
 * and was modified by Michael Leslie <mleslie> of
 * Arcturus Networks Inc. <arcturusnetworks.com> in 2004
 *
 * Copyright (c) 2003 Miriam Technologies Inc. <uclinux@miriamtech.com>
 * Copyright (c) 2003 Engineering Technologies Canada Ltd. (engtech.ca)
 * Copyright (c) 2003 Travis Griggs <tgriggs@keyww.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <getopt.h>

#ifdef __uClinux__
#include <asm/coldfire.h>
#include <asm/mcfqspi.h>
#include <asm/mcfsim.h>
#endif

uint8_t  port = 1;
uint32_t cpol = 0;
uint32_t cpha = 0;
int      chan = 0;
int      N    = 1;

int32_t serialPort;
char * programName;



int spiRead(uint8_t registerIndex)
{
	int registerValue = 0;
	uint32_t count;

#ifdef __uClinux__
	qspi_read_data readData;

	/* readData.buf[0] = 3; */ /* 2r11 is the read command */

	if (chan == 0)
	  readData.buf[0] = 0xc0 >> 3; /* channel 0 */
	else if (chan == 1)
	  readData.buf[0] = 0xe0 >> 3; /* channel 1 */

	readData.buf[1] = registerIndex;
	readData.length = 4;
	readData.loop = 0;
	if (ioctl(serialPort, QSPIIOCS_READDATA, &readData)) perror("QSPIIOCS_READDATA"); 
	count = read(serialPort, &registerValue, 4);
	if(count != 4) perror("read");
#endif
	return registerValue;
}



static int32_t parse_args(int argc, char **argv) {
	static const struct option options[] = {
		{"port", 1, 0, 'p'},
		{"cpol", 1, 0, 'l'},
		{"cpha", 1, 0, 'a'},
		{"chan", 1, 0, 'c'},
		{"iter", 1, 0, 'n'},
		{ 0, 0, 0, 0 }
 	};

 	int32_t c, index, consumedArgs = 0;
				 
 	while((c = getopt_long(argc, argv, "p:l:a:c:n:", options, &index)) != -1) {
 		switch(c) {
			case 'p': port = atoi(optarg); consumedArgs+=2; break;
			case 'l': cpol = (atoi(optarg) != 0); consumedArgs+=2; break;
			case 'a': cpha = (atoi(optarg) != 0); consumedArgs+=2; break;
			case 'c': chan = (atoi(optarg) != 0); consumedArgs+=2; break;
			case 'n': N    = atoi(optarg); consumedArgs+=2; break;
			default:
				printf("unknown option\n");
				break;
		}
	}
	return consumedArgs;
}
	 
int main (int argc, char** argv)
{
    int32_t baudRate;
    int32_t lessArgc;
    char*   commandName;
    char    devicePath[BUFSIZ];
    int     i;
    unsigned int j;
    unsigned short  *buf;

    programName = argv[0];

    lessArgc = parse_args(argc, argv);

    sprintf(devicePath, "/dev/qspi1");

    // printf("%s --port %d --cpol %d --cpha %d\n", argv[0], port, cpol, cpha);

#ifdef __uClinux__
    serialPort = open(devicePath, O_RDWR);
    if(serialPort < 0) {
      perror("open");
      exit(1);
    }

    if(ioctl(serialPort, QSPIIOCS_DOUT_HIZ, 0)) perror("QSPIIOCS_DOUT_HIZ");
    if(ioctl(serialPort, QSPIIOCS_BITS, 16)) perror("QSPIIOCS_BITS");
    if(ioctl(serialPort, QSPIIOCS_CPOL, cpol)) perror("QSPIIOCS_CPOL");
    if(ioctl(serialPort, QSPIIOCS_CPHA, cpha)) perror("QSPIIOCS_CPHA");
    /* baudRate = 8; */ /* (MCF_CLK / (2 * 5000000)) = 4.8, rounded up to 8 */
    baudRate = 66; /* (MCF_CLK / (2 * 5e5)) = 66 */
    if(ioctl(serialPort, QSPIIOCS_BAUD, baudRate)) perror("QSPIIOCS_BAUD");
#endif

    buf = malloc (N * sizeof (short));

    /* Note that the shift value below was
     * arrived at by trial and error... */
    for (i=0;i<N;i++) {
      j = spiRead (0);
      j = j >> 12;
      buf[i] = (unsigned short)j;
    }

    printf ("%d measurements were made from from ADC Channel %i:\n\n", N, chan);
    for (i=0;i<N;i++)
      printf ("   0x%03X%s", buf[i], ((i+1)%4)?"":"\n");
    printf ("\n\n");

    free (buf);
    return 0;
}
