/*
 * YAFFS: Yet another FFS. A NAND-flash specific file system. 
 * mkyaffs.c Format a chunk of NAND for YAFFS.
 *
 * Copyright (C) 2002 Aleph One Ltd.
 *   for Toby Churchill Ltd and Brightstar Engineering
 *
 * Created by Charles Manning <charles@aleph1.co.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Acknowledgement:
 *  This file is crafted from nandtest.c by  Miguel Freitas (miguel@cetuc.puc-rio.br)
 *  and Steven J. Hill (sjhill@cotw.com)
 *
 * Overview:
 * Formatting a YAFFS device is very simple. Just erase all undamaged blocks. 
 * NB Don't erase blocks maked as damaged.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <asm/types.h>
#include "../mtd/mtd-user.h"

const char *mkyaffs_c_version = "$Id: mkyaffs.c 2012 2006-01-09 10:30:55Z aubrey $";

// countBits is a quick way of counting the number of bits in a byte.
// ie. countBits[n] holds the number of 1 bits in a byte with the value n.

static const char countBits[256] =
{
0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8
};

/*
 * Buffer arrays used for running tests
 */

unsigned char oobbuf[16];
unsigned char imgpage[528];

/*
 * OOB layout
 */

struct nand_oobinfo yaffs_oobinfo = {
	useecc: 1,
	eccpos: {8, 9, 10, 13, 14, 15}
};

struct nand_oobinfo yaffs_noeccinfo = {
	useecc: 0,
};


/*
 * Main program
 */
int main(int argc, char **argv)
{
	unsigned long addr;
	unsigned long offset;
	int fd;
	int img=-1;
	int optcnt = 1;
	int usemtdecc = 0;
	int imglen = 0;
	int showHelp = 0;
	struct mtd_oob_buf oob = {0, 16, (unsigned char *) &oobbuf};
	mtd_info_t meminfo;
	erase_info_t erase;
	struct nand_oobinfo oobsel;

	if (argc > 1 && strcmp (argv[optcnt], "-?") == 0) {
		showHelp = 1;
	}

	if (argc > 1 && strcmp (argv[optcnt], "-h") == 0) {
		showHelp = 1;
	}
	
	if (argc > 1 && strcmp (argv[optcnt], "-e") == 0) {
		optcnt++;
		usemtdecc = 1;
	}
	
	printf("argc %d sh %d optcnt %d\n",argc, showHelp, optcnt);
	
	/* Make sure a device was specified */
	if(showHelp || argc < (optcnt + 1)) {
		printf("usage: %s [-e] <mtdname> [image name]\n", argv[0]);
		printf("  -e         Use mtd ecc. Default: do not use mtd ecc\n");
		printf("  mtdname    Name of mtd device\n");
		printf("  image name Name of optional image file\n\n");
		printf("Function: Formats a NAND mtd device for YAFFS. If the optional\n"
		       "image file is specified, then the file system is loaded with\n"
		       "this image.\n\n");
		exit(1);
	}

	if( argc > (optcnt + 1) &&
	    (img = open(argv[optcnt + 1],O_RDONLY)) == -1) {
		perror("opening image file");
		exit(1);
	}
	
	if(img >= 0){
	   imglen = lseek(img,0,SEEK_END);
	   if(imglen %528){
	   	printf("Image not a multiple of 528 bytes\n");
	   	exit(1);
	   }
	}
	
	lseek(img,0,SEEK_SET);

	/* Open the device */
	if((fd = open(argv[optcnt], O_RDWR)) == -1) {
		perror("opening flash");
		exit(1);
	}

	/* Fill in MTD device capability structure */
	if(ioctl(fd, MEMGETINFO, &meminfo) != 0) {
		perror("MEMGETINFO");
		close(fd);
		exit(1);
	}

	// set the appropriate oob layout selector
	oobsel = usemtdecc ? yaffs_oobinfo : yaffs_noeccinfo;
	if (ioctl (fd, MEMSETOOBSEL, &oobsel) != 0) {
		perror ("MEMSETOOBSEL");
		close (fd);
		exit (1);
	} 

	/* Make sure device page sizes are valid */
	if( !(meminfo.oobsize == 16 && meminfo.oobblock == 512)) 
	{
		printf("Unknown flash (not normal NAND)\n");
		close(fd);
		exit(1);
	}
	
	if(imglen >= 0 &&
	   (imglen/528 +32)*512 > meminfo.size){
		printf("Image is too big for NAND\n");
		exit(1);
	}
	
	
	printf("Erasing and programming NAND\n");
	for(addr = 0; addr < meminfo.size; addr += meminfo.erasesize)
	{
		/* Read the OOB data to determine if the block is valid.
		 * If the block is damaged, then byte 5 of the OOB data will
		 * have at least 2 zero bits.
		 */
		oob.start = addr;
		oob.length = 16;
		oob.ptr = oobbuf;
		if (ioctl(fd, MEMREADOOB, &oob) != 0) 
		{
			perror("ioctl(MEMREADOOB)");
			close(fd);
			exit(1);
		}
		
		if(countBits[oobbuf[5]] < 7)
		{
			printf("Block at 0x08%lx is damaged and is not being formatted\n",addr);
		}
		else
		{
			/* Erase this block */
			erase.start = addr;
			erase.length = meminfo.erasesize;
			printf("Erasing block at 0x08%lx\n",addr);
			if(ioctl(fd, MEMERASE, &erase) != 0) 
			{
				perror("\nMTD Erase failure\n");
				close(fd);
				exit(1);
			}
			
			/* Do some programming, but not in the first block */
			
			if(addr){
				for(offset = 0; offset <meminfo.erasesize; offset+=512)
				{
					if(read(img,imgpage,528) == 528){
						if (usemtdecc) {
							imgpage[512+8] = 0xff;
							imgpage[512+9] = 0xff;
							imgpage[512+10] = 0xff;
							imgpage[512+13] = 0xff;
							imgpage[512+14] = 0xff;
							imgpage[512+15] = 0xff;
						}
						oob.start = addr+offset;
						oob.length=16;
						oob.ptr=&imgpage[512];
						ioctl(fd,MEMWRITEOOB,&oob);

						lseek(fd,addr+offset,SEEK_SET);
						write(fd,imgpage,512);
					}
				}
			}
			
		}

	}



	/* All the tests succeeded */
	printf("OK\n");
	close(fd);
	return 0;
}

