/*********************************************************************
 *                
 * Filename:      dongle_attach.c
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Mon May 10 23:58:45 1999
 * Modified at:   Wed Oct  6 20:22:48 1999
 * Modified by:   Dag Brattli <dagb@cs.uit.no>
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *     
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License 
 *     along with this program; if not, write to the Free Software 
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 *     MA 02111-1307 USA
 *     
 ********************************************************************/

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include <asm/byteorder.h>

#include <net/if.h>
#include <linux/types.h>
#include <irda.h>

#ifndef AF_IRDA
#define AF_IRDA 23
#endif /* AF_IRDA */

/*
 * Function main (argc, )
 *
 *    Initialize and try to receive test frames
 *
 */
int main(int argc, char *argv[])
{
	struct ifreq ifr;
	char dev[10];
	int dongle = -1;
	int c;
	int fd;

	if (argc < 3) {
		printf("Usage: dongle_attach <device> -d <dongle>\n");
		printf("\nExample: dongle_attach irda0 -d esi\n\n");
		exit(-1);
	}
	
	strcpy(dev, argv[1]);

	while ((c = getopt(argc, argv, "d:")) != -1) {
		switch (c) {
		case 'd':
			if (strcmp(optarg, "esi") == 0)
				dongle = IRDA_ESI_DONGLE;
			else if (strcmp(optarg, "tekram") == 0)
				dongle = IRDA_TEKRAM_DONGLE;
			else if (strcmp(optarg, "actisys") == 0)
				dongle = IRDA_ACTISYS_DONGLE;
			else if (strcmp(optarg, "actisys+") == 0)
				dongle = IRDA_ACTISYS_PLUS_DONGLE;
			else if (strcmp(optarg, "girbil") == 0)
				dongle = IRDA_GIRBIL_DONGLE;
			else if (strcmp(optarg, "litelink") == 0)
				dongle = IRDA_LITELINK_DONGLE;
			else if (strcmp(optarg, "airport") == 0)
				dongle = IRDA_AIRPORT_DONGLE;
			else if (strcmp(optarg, "old_belkin") == 0)
				dongle = IRDA_OLD_BELKIN_DONGLE;
			else if (strcmp(optarg, "ep7211") == 0)
				dongle = IRDA_EP7211_IR;
			else if (strcmp(optarg, "mcp2120") == 0)
				dongle = IRDA_MCP2120_DONGLE;
			else if (strcmp(optarg, "act200l") == 0)
				dongle = IRDA_ACT200L_DONGLE;
			else if (strcmp(optarg, "ma600") == 0)
				dongle = IRDA_MA600_DONGLE;
			
			if (dongle == -1) {
				printf("Sorry, dongle not supported yet!\n");
				exit(-1);
			}
			break;
		default:
			break;
		} 
	}
	/* Create socket */
	fd = socket(AF_IRDA, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
        }

        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_data = (void *) dongle;

	if (ioctl(fd, SIOCSDONGLE, &ifr) < 0) {
		perror("ioctl");
		exit(-1);
	}
	return 0;
}
