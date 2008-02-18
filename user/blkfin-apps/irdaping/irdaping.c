/*********************************************************************
 *                
 * Filename:      irdaping.c
 * Version:       0.4
 * Description:   Ping tool for irda frames
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Sat Feb 20 02:09:06 1999
 * Modified at:   Tue Sep  7 21:00:24 1999
 * Modified by:   Dag Brattli <dagb@cs.uit.no>
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *      
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version.
 *  
 *     Neither Dag Brattli nor University of Tromsø admit liability nor
 *     provide warranty for any of this software. This material is 
 *     provided "AS-IS" and at no charge.
 *     
 ********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>		/* For struct ifreq */
#include <net/if_packet.h>	/* For struct sockaddr_pkt */
#include <net/if_arp.h>		/* For ARPHRD_IRDA */
#include <netinet/if_ether.h>	/* For ETH_P_ALL */
#include <netinet/in.h>		/* For htons */

/* 
 * We should not really include kernel header files, but they are currently
 * the only ones that knows anything about IrDA and byte ordering.
 */

#include <asm/byteorder.h>	/* __cpu_to_le32 and co. */

#include <linux/types.h>	/* For __u8 and co. */
#include "irda.h"

#ifndef AF_IRDA
#define AF_IRDA    23        /* <linux/socket.h> */
#define PF_IRDA    AF_IRDA
#endif /* AF_IRDA */

#define TEST_FRAME 0xe3
#define CMD_FRAME  0x01
#define RSP_FRAME  0x00

#define PF_BIT 0x10 /* Poll/final bit */

#define BROADCAST  0xffffffff /* Broadcast device address */
#define CBROADCAST 0xfe       /* Connection broadcast address */

#define DEV_DEFAULT "irda0"

struct test_frame {
	__u8 caddr;          /* Connection address */
	__u8 control;
	__u32 saddr;         /* Source device address */
	__u32 daddr;         /* Destination device address */
	__u8 info[0];        /* Information */
} __attribute__((packed));

struct test_info {
	__u16  pkt_nr;
	struct timeval time;
	__u8 info[0];
} __attribute__((packed));

/* Group together all globals */
struct instance {
	int    fd;          /* Socket */
	int    packets;     /* Number of frames received */
	__u32  saddr;       /* Source device address */
	__u32  daddr;       /* Destination device address */
	struct ifreq ifr;
	int    framelen;    /* How large frames we should send */
	char   device[14];  /* Name of device, usually "irda0" */
	struct timeval time_current;
	__u8 buf[2048];
} self;

/*
 * Function cleanup (signo)
 *
 *    Called at exit. Just print number of frames received.
 *
 */
void cleanup(int signo)
{
	fflush(stdout);
	putc('\n', stdout);

	printf("%d packets received by filter\n", self.packets);
	
	exit(0);
}

/*
 * Function timeout (signo)
 *
 *    Is called every time we should send a frame
 *
 */
void timeout(int signo)
{
	struct test_frame *frame;
	struct test_info  *info;
	struct sockaddr_pkt from;
	int n=0;
	int i;
	int count, rest;

	frame = (struct test_frame *) self.buf;
	info = (struct test_info *) frame->info;

	/* Build ping test frame */	
	self.saddr = *((__u32*) self.ifr.ifr_hwaddr.sa_data);
	
	frame->caddr   = CBROADCAST | CMD_FRAME;
	frame->control = TEST_FRAME | PF_BIT;
	frame->saddr = __cpu_to_le32(self.saddr);
	frame->daddr = __cpu_to_le32(self.daddr);
	
	info->pkt_nr = __cpu_to_le16(self.packets++);
	gettimeofday(&self.time_current, (struct timezone*) 0);
	memcpy(&info->time, &self.time_current, sizeof(struct timezone));

	/* Fill in some data in rest of frame */
	rest = self.framelen-sizeof(struct test_frame)-sizeof(struct test_info);
	for (i=0;i<rest;i++) {
		info->info[i] = n++;
	}
	
	from.spkt_family = ARPHRD_IRDA;
	from.spkt_protocol = htons(AF_IRDA);
	memcpy(from.spkt_device, self.device, 6);
	
	count = sendto(self.fd, self.buf, self.framelen, 0, 
		       (struct sockaddr *) &from, sizeof(from));
	if (count < 0) {
		perror("sendto");
		exit(-1);
	}
}

/*
 * Function main (argc, )
 *
 *    Initialize and try to receive test frames
 *
 */
int main(int argc, char *argv[])
{
	int count;
	struct test_frame *frame;
	struct test_info *info;
	unsigned char buf[2048];
	struct sockaddr from_sa;
	struct sockaddr_pkt from;
	socklen_t fromlen;
	struct timeval time, *timep;
	struct itimerval itime;
	float diff;
	int c;
	
	if (argc < 2) {
		printf("Usage: irdaping <daddr> [-s <framesize>] [-i <iface>]\n");
		exit(-1);
	}
	
	/* Initialize */
	memset(&self, 0, sizeof(struct instance));
	self.daddr = (__u32) strtoul(argv[1], NULL, 0);
	self.framelen = 32;
	strncpy(self.device, DEV_DEFAULT, 14);

	while ((c = getopt(argc, argv, "hs:i:")) != -1) {
		switch (c) {
		case 's': /* Packet size */
			self.framelen = strtol(optarg, NULL, 10);
			break;
		case 'i': /* Interface name */
			strncpy(self.device, optarg, 14);
			break;
		case 'h': /* Help */
			printf("Usage: irdaping <daddr> [-s <framesize>] [-i <iface>]\n");
			exit(-1);
		default:
			break;
		} 
	}

	/* Correct the framesize */
        if (self.framelen < (12+sizeof(struct timeval)))
		self.framelen = 12+sizeof(struct timeval);
	
        /* Eventually we should use sigaction instead */
	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGHUP, cleanup);
	signal(SIGALRM, timeout);
	
        /* Create socket */
	self.fd = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));
	if (self.fd < 0) {
		perror("socket");
		exit(-1);
        }
	
	/* Bind to the interface */
        memset(&from_sa, 0, sizeof(from_sa));
	from_sa.sa_family = AF_PACKET;
        strncpy(from_sa.sa_data, self.device, sizeof(from_sa.sa_data));
        if (bind(self.fd, &from_sa, sizeof(from_sa))) {
		perror("bind");
		exit(-1);
        }
	
        /* Get source device address */
	memset(&self.ifr, 0, sizeof(self.ifr));
	strncpy(self.ifr.ifr_name, self.device, sizeof(self.ifr.ifr_name));
        if (ioctl(self.fd, SIOCGIFHWADDR, &self.ifr) < 0 ) {
		perror("SIOCGIFHWADDR");
		exit(-1);
        }
	itime.it_value.tv_sec = 1;
	itime.it_value.tv_usec = 0;
	
	itime.it_interval.tv_sec = 1;
	itime.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &itime, NULL);
	
	printf("IrDA ping (0x%08x on %s): %d bytes\n", self.daddr, self.device, self.framelen);
	
	while(1) {
		fromlen = sizeof(struct sockaddr_pkt);
		count = recvfrom(self.fd, buf, 2048, 0, 
				 (struct sockaddr *) &from, &fromlen);
		if (count < 0) {
			perror("recvfrom");
			exit(-1);
		}
		
		frame = (struct test_frame *) buf;
		info = (struct test_info *) frame->info;
		
		/* Assert that this is really a test response frame */
		if ((frame->caddr & CMD_FRAME) || 
		    (frame->control != (TEST_FRAME|PF_BIT)))
			continue;

		if (count < sizeof(struct test_frame))
			continue;

		printf( "%d bytes from ", count);
 		printf( "0x%08x", __le32_to_cpu(frame->saddr));
		
		/* Check if frame contains any addtional info */
		if (count < (sizeof(struct test_frame)+
			     sizeof(struct test_info))) {
			printf("\n");
			continue;
		}

		gettimeofday(&time, (struct timezone*) 0);
		
		/* Read time from frame */
                timep = &info->time;
		
                if (timep->tv_usec > time.tv_usec) {
                        time.tv_usec += 1000000;
                        time.tv_sec--;
                }
                time.tv_usec = time.tv_usec - timep->tv_usec;
                time.tv_sec = time.tv_sec - timep->tv_sec;
                
                diff = ((float) time.tv_sec * 1000000.0 + time.tv_usec)
                        / 1000.0;
		
		printf( ": irda_seq=%d ", __le16_to_cpu(info->pkt_nr));
 		printf( "time=%6.2f ms.\n", diff);
	}
}




