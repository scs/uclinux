/*
 * avrecv.c
 * This program does basic AVRCP reception (TG)
 *
 * Brad Midgley <bmidgley@xmission.com>
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include "avrcp.h"

// before running the daemon, publish the sdp record:
// sdptool add AVRTG
// or publish it ourself 

static volatile int terminate = 0;
#define BUFS 512

// Prepare packet headers
static void init_response(struct avctp_header *header)
{
	header->ipid = 0;
	header->cr = AVCTP_RESPONSE_FRAME;
	header->packet_type = PACKET_TYPE_SINGLE;
}

static int do_listen(bdaddr_t *src, unsigned short psm)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk;
	unsigned int opt;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		fprintf(stderr, "Can't create socket. %s(%d)\n",
			strerror(errno), errno);
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);
	addr.l2_psm=htobs(psm);
	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Can't bind socket. %s(%d)\n",
						strerror(errno), errno);
		return -1;
	}
	
	/* Get default options */
	opt = sizeof(opts);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		fprintf(stderr, "Can't get default L2CAP options. %s(%d)\n",
						strerror(errno), errno);
		return -1;
	}
	
	/* Set new options */
	//opts.omtu = 48;
	//opts.imtu = imtu;
	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, opt) < 0) {
		fprintf(stderr, "Can't set L2CAP options. %s(%d)\n",
						strerror(errno), errno);
		return -1;
	}

	if(listen(sk,5)<0) {
		fprintf(stderr,"\nCan't listen.%s(%d)\n",strerror(errno),errno);
		close(sk);
		return -1;
	}

	return sk;
}

static int do_accept(int serverfd, bdaddr_t *remote, uint16_t *mtu)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	socklen_t addrlen;
	int nsk;
	unsigned int opt;

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if ((nsk = accept(serverfd, (struct sockaddr *) &addr, &addrlen)) < 0)
		return -1;
	else printf("\nConnected");
	
	opt = sizeof(opts);
	if (getsockopt(nsk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		fprintf(stderr, "Can't get L2CAP options. %s(%d)\n",
						strerror(errno), errno);
		close(nsk);
		return -1;
	}

	fprintf(stderr, "Connected [imtu %d, omtu %d, flush_to %d]\n",
					opts.imtu, opts.omtu, opts.flush_to);

	if (mtu)
		*mtu = opts.omtu;
	if (remote) 
		bacpy(remote, &addr.l2_bdaddr);

	return nsk;
}

#if 1
static void dump_packet(void *p, int size)
{
	struct avc_frame *f = p;
	uint8_t *c = (uint8_t *) p;
	while (size-- > 0)
		printf(" %02x\n", *c++);
	printf("\n");

	if(size >= sizeof(struct avc_frame)) {
		printf("transaction_label = %x\n", f->header.transaction_label );
		printf("packet_type = %x\n", f->header.packet_type );
		printf("cr = %x\n", f->header.cr );
		printf("ipid = %x\n", f->header.ipid );
		printf("pid = %x\n", f->header.pid );
		printf("zeroes = %x\n", f->zeroes );
		printf("ctype = %x\n", f->ctype );
		printf("subunit_type = %x\n", f->subunit_type );
		printf("subunit_id = %x\n", f->subunit_id );
		printf("opcode = %x\n", f->opcode );
		printf("operand0 = %x\n", f->operand0 );
		printf("operand1 = %x\n", f->operand1 );
	}
}
#endif

int main(int argc, char *argv[])
{
	int serverfd, cmdfd = -1;
	bdaddr_t local_addr, remote_addr;
	struct avc_frame frame;
	int size;

	// unit info, subunit info, vendor dependent, passthrough
	// av/c command/response frames within avctp c/r message information field
	// avrcp p.27

	// categories (avrcp feature flags)
	// 0001 player
	// 0010 monitor
	// 0100 tuner
	// 1000 menu

	// parameter 0 for protocol avctp 0x0100
	// parameter 0 for profile avrcp 0x0100

	// service class a/v rcp target

	// 48-byte min mtu

	bacpy(&local_addr, BDADDR_ANY);

	serverfd = do_listen(&local_addr, L2CAP_PSM_AVCTP);
	if(serverfd < 0) {
		printf("couldn't listen on %d\n", L2CAP_PSM_AVCTP);
		exit(1);
	}

	while(!terminate) {
		if(cmdfd != -1) close(cmdfd);
		printf("accepting next connection\n");
		cmdfd = do_accept(serverfd, &remote_addr, NULL);
		if(cmdfd < 0) break;

		do {
			size = read(cmdfd, &frame, sizeof(frame));
			if(frame.ctype == CMD_PASSTHROUGH) {
				switch (frame.operand0) {
				case PLAY_OP:
					printf("[play]\n");
					break;
				case PAUSE_OP:
					printf("[pause]\n");
					break;
				case NEXT_OP:
					printf("[next]\n");
					break;
				case PREV_OP:
					printf("[previous]\n");
					break;
				default:
					printf("received passthrough %d bytes:\n", size);
					dump_packet(&frame, size);
				}
			} else {
				printf("received %d bytes:\n", size);
				dump_packet(&frame, size);
			}
			if(size > 0) {
				if(frame.ctype == CMD_ACCEPTED) {
					printf("(ack)\n");
				} else if(frame.ctype == CMD_PASSTHROUGH) {
					init_response(&frame.header);
					frame.ctype = CMD_ACCEPTED;
					write(cmdfd, &frame, size);
				} else {
					printf("only passthrough ctype command is implemented. doh!\n");
					exit(0);
				}
			}
		} while(size >0);
	}

	close(serverfd);

	return 0;
}
