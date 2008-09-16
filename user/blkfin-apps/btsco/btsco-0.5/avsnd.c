/*
 * avrecv.c
 * This program makes an outgoing AVRCP connection to the headset 
 * and receives basic AVRCP control
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

static volatile int terminate = 0;
#define BUFS 512

// Prepare packet headers
static void init_command(struct avctp_header *header)
{
	static int transaction = 0;

	header->ipid = 0;
	header->cr = AVCTP_COMMAND_FRAME;
	header->packet_type = PACKET_TYPE_SINGLE;
	header->transaction_label = transaction;
	header->pid = AVRCP_PID;

	transaction = (transaction + 1) & 0xf;
}

// Prepare packet headers
static void init_response(struct avctp_header *header)
{
	header->ipid = 0;
	header->cr = AVCTP_RESPONSE_FRAME;
	header->packet_type = PACKET_TYPE_SINGLE;
}

static int do_connect(bdaddr_t *src, bdaddr_t *dst, unsigned short psm, uint16_t *mtu)
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
	if(mtu && *mtu) {
		opts.omtu = *mtu;
		//opts.imtu = *mtu;
	}
	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, opt) < 0) {
		fprintf(stderr, "Can't set L2CAP options. %s(%d)\n",
						strerror(errno), errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(psm);
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Can't connect to %s. %s(%d)\n",
			batostr(&addr.l2_bdaddr), strerror(errno), errno);
		close(sk);
		return -1;
	}

	opt = sizeof(opts);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		fprintf(stderr, "Can't get L2CAP options. %s(%d)\n",
						strerror(errno), errno);
		close(sk);
		return -1;
	}

	fprintf(stderr, "Connected [imtu %d, omtu %d, flush_to %d]\n",
					opts.imtu, opts.omtu, opts.flush_to);

	if (mtu)
		*mtu = opts.omtu;

	return sk;
}

#if 1
static void dump_packet(void *p, int size)
{
	uint8_t *c = (uint8_t *) p;
	while (size-- > 0)
		printf(" %02x\n", *c++);
	printf("\n");
}
#endif

int main(int argc, char *argv[])
{
	int cmdfd = -1;
	bdaddr_t local_addr, remote_addr;
	struct avc_frame frame;
	int size;
	char *addrstr;

	if(argc != 2) {
		fprintf(stderr, "use: avsnd <dest>\n");
		exit(1);
	}

	addrstr = argv[1];
	fprintf(stderr, "Using address: %s\n", addrstr);
	str2ba(addrstr, &remote_addr);
	bacpy(&local_addr, BDADDR_ANY);

	cmdfd = do_connect(&local_addr, &remote_addr, L2CAP_PSM_AVCTP, NULL);

	if(cmdfd < 0) {
		fprintf(stderr, "can't connect to %s\n", addrstr);
		exit(1);
	}

	while(!terminate) {

		//printf("command? [u]p [d]own [q]uit > ");

		sleep(1); 
		printf("sending volume-up\n");				
		frame.operand0 = VOLUP_OP;

		size = sizeof(frame);
		init_command(&frame.header);
		frame.ctype = CMD_PASSTHROUGH;
		frame.opcode = OP_PASS;
		frame.operand1 = 0;
		frame.zeroes = 0;
		frame.subunit_id = 0;
		frame.subunit_type = SUBUNIT_PANEL;

		printf("sending command\n");
		dump_packet(&frame, size);
		write(cmdfd, &frame, size);

		printf("waiting for reply...\n");

		size = read(cmdfd, &frame, sizeof(frame));
		if(size > 0) {
			if(frame.ctype == CMD_ACCEPTED) {
				printf("(ack)\n");
			} else if(frame.ctype == CMD_PASSTHROUGH) {
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

				init_response(&frame.header);
				frame.ctype = CMD_ACCEPTED;
				write(cmdfd, &frame, size);
			} else {
				printf("unrecognized frame\n");
				dump_packet(&frame, size);
			}
		} else {
			printf("no response\n");
			terminate = 1;
		}

	}

	close(cmdfd);

	return 0;
}
