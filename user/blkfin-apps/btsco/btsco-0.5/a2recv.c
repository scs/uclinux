/*
 * a2recv.c
 * This program functions as an A2DP sink
 * (Emulation of an A2DP headset)
 * Mayank Batra  <mayankbatra@yahoo.co.in>
 * Abhinav Mathur <abhinavpmathur@yahoo.com>
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
#include <sys/soundcard.h>	//To play the sound on the sound card

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include "sbc/sbc.h"

#define MAX_ADDITIONAL_CODEC 0	//Right now only SBC is supported
#include "a2dp.h"

#define BUFS 1024

static volatile int terminate = 0;
sbc_t sbc;
int audio_fd;
#define BUF_SIZE 4096
unsigned char audio_buffer[BUF_SIZE];
int speed, channels;

int adjustsound()
{
	if(ioctl(audio_fd,SNDCTL_DSP_CHANNELS,&channels)==-1) {
		perror("\nioctl no. 2\n");
		exit(1);
	}

	if(ioctl(audio_fd,SNDCTL_DSP_SPEED,&speed)==-1) {
		perror("\nioctl no. 3\n");
		exit(1);
	}

	return 1;
}

int opensound()
{
#ifdef FORCE_LITTLE
	int format=AFMT_S16_LE;
#else
	int format=AFMT_S16_BE;
#endif
	//int len,i;
	//char c;

	if((audio_fd=open("/dev/dsp",O_WRONLY,0))==-1) {
		perror("\nFile open error\n");
		exit(1);
	}
	if(ioctl(audio_fd,SNDCTL_DSP_SETFMT,&format)==-1) {
		perror("\nioctl no. 1\n");
		exit(1);
	}

	return adjustsound();
}

int closesound()
{
	if(close(audio_fd)<0) {
		perror("\nUnable to close the sound card");
		exit(1);
	}
	return 0;
}

static void decode(char *stream,int streamlen)
{
	//int fd, id;
#ifdef FORCE_LITTLE
	int i;
	char temp;
	char *ptr;
#endif
	int pos, framelen;
	pos = 0;

	framelen = sbc_decode(&sbc, stream, streamlen);

	if(sbc.channels != channels || sbc.rate != speed) {
		printf("rate/channels changed to %d Hz, %d channels\n", sbc.rate, sbc.channels);
		channels=sbc.channels;
		speed=sbc.rate;
		adjustsound();
	}

#ifdef FORCE_LITTLE
	ptr = sbc.data;
#endif

	//char c;
	while (framelen > 0) {
#ifdef FORCE_LITTLE
		for(i=0; i<sbc.len; i+=2) {
			temp = ptr[i];
			ptr[i] = ptr[i+1];
			ptr[i+1] = temp;
		}
#endif
		//dump_packet(sbc.data,sbc.len);
		write(audio_fd,sbc.data,sbc.len);
	
		pos += framelen;
		if(streamlen - pos <= 0)
			break;

		framelen = sbc_decode(&sbc, stream + pos, streamlen - pos);
	}

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

// copied from hcitool.c
static int find_conn(int s, int dev_id, long arg)
{
        struct hci_conn_list_req *cl;
        struct hci_conn_info *ci;
        int i;

        if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
                perror("Can't allocate memory");
                exit(1);
        }
        cl->dev_id = dev_id;
        cl->conn_num = 10;
        ci = cl->conn_info;

        if (ioctl(s, HCIGETCONNLIST, (void *) cl)) {
                perror("Can't get connection list");
                exit(1);
        }

        for (i = 0; i < cl->conn_num; i++, ci++)
                if (!bacmp((bdaddr_t *) arg, &ci->bdaddr))
                        return 1;

        return 0;
}

// based on cmd_sr() from hcitool.c
static void make_master(bdaddr_t bdaddr)
{
        uint8_t role = 0; // 0 means master
        int dd, dev_id;

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
	if (dev_id < 0) {
		fprintf(stderr, "make_master: Not connected.\n");
		return;
	}

        dd = hci_open_dev(dev_id);
        if (dd < 0) {
                perror("HCI device open failed");
		return;
        }

#ifndef HAVE_NO_HCI_SWITCH_ROLE
	/* Older versions of bluez-libs got the second argument
	 * wrong, hci_switch_role is expecting a pointer to
	 * a bdaddr_t */
        if (hci_switch_role(dd, &bdaddr, role, 10000) < 0) {
                perror("Switch role request failed");
        }
#endif
        close(dd);
}

#if 0
static void dump_packet(void *p, int size)
{
	uint8_t *c = (uint8_t *) p;
	while (size-- > 0)
		printf(" %02x\n", *c++);
	printf("\n");
}
#endif

static void init_response(struct avdtp_header * header, const struct avdtp_header * request)
{
	header->packet_type = PACKET_TYPE_SINGLE;
	header->message_type = MESSAGE_TYPE_ACCEPT;
	header->transaction_label = request->transaction_label;
	header->signal_id = request->signal_id;

	// clear rfa bits
	header->rfa0 = 0;
}

int main(int argc, char *argv[])
{
	int serverfd, cmdfd = -1, streamfd = -1;
	bdaddr_t local_addr, remote_addr;
	unsigned short psm_cmd;
	uint16_t seq_num;
	struct sepd_resp send_resp;
	struct getcap_req *get_req;
	struct getcap_resp cap_resp;
	struct set_config *s_config;
	struct set_config_resp s_resp;
	struct open_stream_rsp open_resp;
	struct start_stream_rsp start_resp;
	struct media_packet_header packet_header;
	struct media_payload_header payload_header;
	struct close_stream_rsp close_resp;
	// States not specified in AVDTP: NOCONN - No cmd connection established
	// OPEN_WAITING - Open Stream Response sent, waiting for L2CAP establishment
	enum { NOCONN, IDLE, CONFIGURED, OPEN_WAITING, OPEN, 
	       STREAMING, CLOSING, ABORTING } state = NOCONN;

	char buf[BUFS];
	
	terminate = 0;
	seq_num = 1;
	
	sbc_init(&sbc,SBC_NULL);

	bacpy(&local_addr, BDADDR_ANY);

	psm_cmd=25;
	serverfd = do_listen(&local_addr, psm_cmd);

	while(!terminate) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(serverfd, &readfds);
		if(state != NOCONN)
			FD_SET(cmdfd, &readfds);
		if(state == STREAMING)
			FD_SET(streamfd, &readfds);
		
		int ready = select(FD_SETSIZE, &readfds, 0, 0, 0);
		if(ready == 0)
			continue;
		if(ready == -1 && errno != EINTR)
			break;

		if(FD_ISSET(serverfd, &readfds) && state == NOCONN) {
			cmdfd = do_accept(serverfd, &remote_addr, NULL);
			if (cmdfd < 0) {
				fprintf(stderr, "cannot open psm_cmd = %d\n", psm_cmd);
				exit(-1);
			}
			state = IDLE;
			continue;
		}
		if(FD_ISSET(serverfd, &readfds) && state == OPEN_WAITING) {
			streamfd = do_accept(serverfd, NULL, NULL);
			if (streamfd < 0) {
				fprintf(stderr, "cannot open psm_stream\n");
				exit(-1);
			}
			printf("Got stream fd\n");
			state = OPEN;
			continue;
		}

		if(state != NOCONN && FD_ISSET(cmdfd, &readfds)) {
			// Read an AVDTP signalling packet
			char packet[BUFS];
			int size = BUFS;
			size = read(cmdfd, &packet, BUFS);

			if(size == -1) {
				perror("Read error on cmd fd");
			}

			if(size == 0 || size == -1) {
				// cmdfd was closed or some error occured
				if(state == CONFIGURED || state == OPEN_WAITING || 
				   state == OPEN || state == STREAMING) {
					closesound();
				}
				if(state == OPEN || state == STREAMING) {
					close(streamfd);
				}
				close(cmdfd);
				state = NOCONN;
				continue;
			}

			// Parse the header
			struct avdtp_header *header = (struct avdtp_header*)&packet;

			if(header->message_type != MESSAGE_TYPE_COMMAND ||
			   header->packet_type != PACKET_TYPE_SINGLE) {
				// We don't handle anything else than single packet commands
				fprintf(stderr, "unsupported packet: "
					"packet type=%i, message type=%i, signal=%i\n", 
					header->packet_type, header->message_type, header->signal_id);
					continue;
			}

			// Check that the size matches our structs
			int proper_size;
			switch(header->signal_id) {
			case AVDTP_DISCOVER:
				proper_size = sizeof(struct sepd_req);
				break;
			case AVDTP_GET_CAPABILITIES:
				proper_size = sizeof(struct getcap_req);
				break;
			case AVDTP_SET_CONFIGURATION:
				proper_size = sizeof(struct set_config);
				break;
			case AVDTP_OPEN:
				proper_size = sizeof(struct stream_cmd);
				break;
			case AVDTP_START:
				proper_size = sizeof(struct stream_cmd);
				break;
			case AVDTP_CLOSE:
				proper_size = sizeof(struct stream_cmd);
				break;
			default:
				fprintf(stderr, "unsupported signalling command: %x\n", 
					header->signal_id);
				continue;
			}

			if(size != proper_size) {
				fprintf(stderr, "packet has wrong size: %i, "
					"should be %i\n", size, proper_size);
				continue;
			}

			// Now parse and handle the packet
			switch(header->signal_id) {
			case AVDTP_DISCOVER:
				//Fill in the values in send_resp
				memset(&send_resp,0,sizeof(send_resp));
				init_response(&send_resp.header, header);
				send_resp.infos[0].rfa0=0;
				send_resp.infos[0].inuse0=(state==IDLE)?0:1;
				send_resp.infos[0].acp_seid=1;
				send_resp.infos[0].rfa2=0;
				send_resp.infos[0].tsep=1;
				send_resp.infos[0].media_type=0;

				if(write(cmdfd,&send_resp,sizeof(send_resp))!=sizeof(send_resp)) {
					fprintf(stderr,"\nCould not send discover response\n");
					close(cmdfd);
					exit(-1);
				}
				else printf("\nSent Stream End Point Discovery Response\n");

				// Stay in the current state
				break;

			case AVDTP_GET_CAPABILITIES:
				get_req = (struct getcap_req*)&packet;

				memset(&cap_resp,0,sizeof(cap_resp));
				init_response(&cap_resp.header, header);
				//Fill in the values of the structure
				cap_resp.serv_cap=MEDIA_TRANSPORT_CATEGORY;
				cap_resp.serv_cap_len=0;
				cap_resp.cap_type=MEDIA_CODEC;
				cap_resp.media_type=AUDIO_MEDIA_TYPE;
				cap_resp.length=6;
				cap_resp.media_codec_type=SBC_MEDIA_CODEC_TYPE;
				cap_resp.codec_elements.sbc_elements.channel_mode=15;
				cap_resp.codec_elements.sbc_elements.frequency=15;
				cap_resp.codec_elements.sbc_elements.allocation_method=3;
				cap_resp.codec_elements.sbc_elements.subbands=3;  
				cap_resp.codec_elements.sbc_elements.min_bitpool=2;
				cap_resp.codec_elements.sbc_elements.max_bitpool=250;
				cap_resp.codec_elements.sbc_elements.block_length=15;

				if(write(cmdfd,&cap_resp,sizeof(cap_resp))<sizeof(cap_resp)) {
					fprintf(stderr,"couldn't reply the caps\n");
				}
				else printf("\nSent the get capabilities response");

				// Stay in the current state
				break;

			case AVDTP_SET_CONFIGURATION:
				s_config = (struct set_config*)&packet;

				channels = ((s_config->codec_elements.sbc_elements.channel_mode&0x08) != 0)?1:2;
				switch(s_config->codec_elements.sbc_elements.frequency) {
				case 0x08: speed = 16000; break;
				case 0x04: speed = 32000; break;
				case 0x02: speed = 44100; break;
				case 0x01: speed = 48000; break;
				default: fprintf(stderr, "funny frequency setting: %x, not supported\n", 
						 s_config->codec_elements.sbc_elements.frequency);
				}

				opensound();
				printf("Channels=%d, speed=%d", channels, speed);

				printf("channel_mode = %d allocation_method = %d subbands = %d block_length = %d min_bitpool = %d max_bitpool = %d\n",
					s_config->codec_elements.sbc_elements.channel_mode,
					s_config->codec_elements.sbc_elements.allocation_method,
                                        s_config->codec_elements.sbc_elements.subbands,
                                        s_config->codec_elements.sbc_elements.block_length,
                                        s_config->codec_elements.sbc_elements.min_bitpool,
                                        s_config->codec_elements.sbc_elements.max_bitpool);

				//Fill in the values of the structure
				memset(&s_resp,0,sizeof(s_resp));
				init_response(&s_resp.header, header);
				if(write(cmdfd,&s_resp,sizeof(s_resp))!=sizeof(s_resp)) {
					fprintf(stderr,"couldn't send set config resp\n");
				}
				else printf("\nSent a Set configurations response\n");

				state = CONFIGURED;
				break;

			case AVDTP_OPEN:
				if(state != CONFIGURED) {
					fprintf(stderr, "open command received but the stream is not configured\n");
					continue;
				}

				struct stream_cmd* open_stream = (struct stream_cmd*)packet;
				printf("\nReceived an open stream command\n");
                                                                              
				memset(&open_resp,0,sizeof(open_resp));
				init_response(&open_resp.header, header);
				if (write(cmdfd, &open_resp, sizeof(open_resp)) < sizeof(open_resp)) {
					fprintf(stderr, "couldn't send open stream response confirm for seid = %d\n", open_stream->acp_seid);
					return (-1);
				}
				
				printf("\nSent open stream confirm\n");
				state = OPEN_WAITING;
				break;

			case AVDTP_START:
				if(state != OPEN) {
					fprintf(stderr, "start command received but the stream is not open\n");
					continue;
				}

				//Fill in the values of the structure
				memset(&start_resp,0,sizeof(start_resp));
				init_response(&start_resp.header, header);
				if (write(cmdfd, &start_resp, sizeof(start_resp)) < sizeof(start_resp)) {
					fprintf(stderr, "Couldn't send start stream command confirm");
					close(streamfd);
					close(cmdfd);
					return (-1);
				}				
				else printf("\nSent start stream confirm\n");

				make_master(remote_addr);

				state = STREAMING;
				break;
			case AVDTP_CLOSE:
				if(state != OPEN && state != STREAMING) {
					fprintf(stderr, "Close stream command received but the stream is not open\n");
					continue;
				}
				
				printf("Got stream-close\n");
				init_response(&close_resp.header, header);
				if (write(cmdfd, &close_resp, sizeof(close_resp)) < sizeof(close_resp)) {
					fprintf(stderr, "Couldn't send close_resp confirm \n");
					close(streamfd);
					close(cmdfd);
					return (-1);
				}
				else printf("Sent close stream confirm\n");
				
				closesound();
				close(streamfd);
				state = IDLE;
			}			
		}

		if(state == STREAMING && FD_ISSET(streamfd, &readfds)) {
			int packsize;
			memset(&buf,0,sizeof(buf));
			packsize = read(streamfd,buf,BUFS);
			//printf("\nRead:%d bytes ",packsize);
			decode(buf+(sizeof(packet_header)+sizeof(payload_header)),(packsize-sizeof(packet_header)-sizeof(payload_header)));

			seq_num++;
		}

	}

	printf("Received %d packets\n", seq_num);
	sbc_finish(&sbc);

	close(serverfd);

	return 0;
}
