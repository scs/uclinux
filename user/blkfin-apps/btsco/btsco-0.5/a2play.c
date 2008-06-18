/*
 * a2play.c
 * experimenting with sending a2dp audio to a headset
 * Brad Midgley
 * *************************************************************************************
 * Mayank Batra <mayankbatra@yahoo.co.in> (Added real time SBC encoding while streaming)
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
#include <malloc.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/soundcard.h>
#include <pthread.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>
#include <linux/rtc.h>

#include "sbc/sbc.h"
#include "a2dp.h"

#define NONSPECAUDIO 1

//Size of the buffer
#define BUFS 1024

//Number of packets to buffer in the ring
#define PACKETBUF 4

static volatile int stop_reading = 0;
static volatile int stop_writing = 0;
static volatile int pause_writing = 0;
static volatile int ring_in = 0;
static volatile int ring_out = 0;
static int cmdfd;
static char buf[PACKETBUF][BUFS];
static int psize[PACKETBUF];
static int streamfd;
static int livestream = 0;
static int verbose = 0;
static int thrifty = 0;
static sbc_t sbc;
static int raw = 0;
static int rtcfd = -1;
static volatile int packetticks;
static pthread_t transmit_pid, listen_pid;

// number of RTC ticks per second... a power of 2 up to 8192
#define TICKS 8192

// For reading count bytes into buf from fd
static ssize_t __read(int fd, void *buf, size_t count)
{
#ifdef FORCE_LITTLE
	int i;
	char c;
	char *ptr;
#endif
        ssize_t len, pos = 0;

        while (count > 0) {
                len = read(fd, buf + pos, count);
                if (len <= 0)
                        return len;
                                                                                                 
                count -= len;
                pos   += len;
        }

#ifdef FORCE_LITTLE
	if(raw) {
		ptr = buf;
		for(i = 0; i < pos; i += 2) {
			c = ptr[i];
			ptr[i] = ptr[i+1];
			ptr[i+1] = c;
		}
	}
#endif
        return pos;
}

#if 0
//For writing count bytes from buf into fd
static ssize_t __write(int fd, const void *buf, size_t count)
{
        ssize_t len, pos = 0;
                                                                                                 
        while (count > 0) {
                len = write(fd, buf + pos, count);
                if (len <= 0)
                        return len;
                                                                                                 
                count -= len;
                pos   += len;
        }
                                                                                                 
        return pos;
}
#endif

#if 0
static void dump_packet(void *p, int size)
{
	uint8_t *c = (uint8_t *) p;
	while (size-- > 0)
		fprintf(stderr, " %02x\n", *c++);
	fprintf(stderr, "\n");
}
#endif

// Detect when the user presses CTRL+C
static void sig_term(int sig)
{
	// allow the next term to actually terminate
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	stop_reading = 1;
}

static void send_packet() 
{
	int idx, written;

	//printf("sending (%d != %d)\n", ring_in, ring_out);
	
	// no data to send
	if(ring_in == ring_out) return;

	
	// find the next packet
	// skip to the last encoded packet if we're live to reduce latency
	do {
		idx = ring_out;
		ring_out = (ring_out+1) % PACKETBUF;
	} while(livestream && ring_in != ring_out);

	written = write(streamfd, buf[idx], psize[idx]);
	if(written == -1) {
		perror("write failed");
		stop_reading = 1;
		stop_writing = 1;
	}
	if(verbose > 1) {
		printf(".");
		fflush(stdout);
	}
}

static void sig_alrm(int sig)
{
	send_packet();
}

static void *transmit_thread(void *init_data) 
{
	unsigned long data;
	int ticks = packetticks;

	// Time reference
	static struct timeval staticcounter = {0,0};
	static int icount = 0;

	while(!stop_writing) {

		static struct timeval timediff = {0,0};
		
	if(staticcounter.tv_sec==0)
	{
		gettimeofday(&staticcounter, NULL);
		gettimeofday(&timediff, NULL);
	}
	
		// blocks until next rtc event
		if(read(rtcfd, &data, sizeof(data)) < sizeof(data)) {
			perror("/dev/rtc read");
			stop_reading = 1;
			break;
		}

	struct timeval timeofday, duration;//, playtime, theoricaldate;
	gettimeofday(&timeofday, NULL);
	timersub(&timeofday, &staticcounter, &duration);

	// Display data once per second
	icount++;
	if(duration.tv_sec>0)
	{
		printf("read %lX %d times / sec.\n", data, icount);
		gettimeofday(&staticcounter, NULL);
		icount=0;
	}
	
		if(pause_writing) {
			sleep(1);
		} else {
			// more than one click may have passed
			// the api docs for /dev/rtc are extremely incomplete
			// status is in the low byte
			// number of ticks since last read is in 3 high bytes
			ticks -= data >> 8;

//			while(ticks <= 0)
			{
				send_packet();
				ticks += packetticks;
			}
		}
	}
	pthread_exit(NULL);
	return NULL;
}

static int compute_ticks(unsigned long sleeptime)
{
	return ((1.0 * TICKS * sleeptime)/(1000000));
}

// Usage
static void usage()
{
	fprintf(stderr, "use: a2play [options] <bdaddr> [filename]\n");
	fprintf(stderr, "Where bdaddr is the bluetooth address of an A2DP headset and\n");
	fprintf(stderr, "filename is an audio file or device, or stdin if not specified.\n\n");

	fprintf(stderr, "Options:\n");
	fprintf(stderr, " -h print this usage and exit\n\n");
	fprintf(stderr, " -f fork and run as a daemon\n");
	fprintf(stderr, " -i use setitimer for packet timing (deprecated)\n");
	fprintf(stderr, " -n send packets as fast as they are encoded instead of timing them (deprecated)\n");
	fprintf(stderr, " -p use pthreads timer (default)\n\n");
	fprintf(stderr, " -t thrifty (repeat for very thrifty)\n");
	fprintf(stderr, " -v print verbose output\n\n");

	fprintf(stderr, " -d process input as raw audio or an audio device\n");
	fprintf(stderr, " -m use mono instead of the default stereo; implies -d\n");
	//fprintf(stderr, " -l data is little-endian instead of default big; implies -d\n");
	fprintf(stderr, " -s skip over backlogged data to try to eliminate latency\n");
	fprintf(stderr, " -r rate (hz): use rate, default 44100, for raw audio or device; implies -d\n\n");
}

// Detect whether A2DP Sink is present at the destination or not
static int detect_a2dp(bdaddr_t *src, bdaddr_t *dst, unsigned short *psm, unsigned long *flags)
{
	sdp_session_t *sess;
	sdp_list_t *attrid, *search, *seq, *next;
	sdp_data_t *pdlist;
	uuid_t group;
	uint32_t range = 0x0000ffff;
	int err;

	sess = sdp_connect(src, dst, SDP_RETRY_IF_BUSY);
	if (!sess) {
		fprintf(stderr, "Warning: failed to connect to SDP server: %s\n", strerror(errno));
		if(psm) *psm = 25;
		if(flags) *flags = 0;
		return 0;
	}

	/* 0x1108->all? 0x1101->rf sink 0x111e->handsfree 0x1108->headset */
	sdp_uuid16_create(&group, 0x110d);
	search = sdp_list_append(0, &group);
	attrid = sdp_list_append(0, &range);
	err = sdp_service_search_attr_req(sess, search,
					SDP_ATTR_REQ_RANGE, attrid, &seq);
	sdp_list_free(search, 0);
	sdp_list_free(attrid, 0);

	if (err) {
		fprintf(stderr, "Service Search failed: %s\n", strerror(errno));
		sdp_close(sess);
		return -1;
	}

	for (; seq; seq = next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;

		fprintf(stderr, "Found A2DP Sink\n");
		if (psm)
			*psm = 25;

		next = seq->next;
		free(seq);
		sdp_record_free(rec);
	}

	sdp_uuid16_create(&group, PNP_INFO_SVCLASS_ID);
	search = sdp_list_append(0, &group);
	attrid = sdp_list_append(0, &range);
	err = sdp_service_search_attr_req(sess, search,
					SDP_ATTR_REQ_RANGE, attrid, &seq);
	sdp_list_free(search, 0);
	sdp_list_free(attrid, 0);

	if (err)
		goto done;

	if (flags)
		*flags = 0;

	for (; seq; seq = next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		uint16_t vendor, product, version;

		pdlist = sdp_data_get(rec, 0x0201);
		vendor = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, 0x0202);
		product = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, 0x0203);
		version = pdlist ? pdlist->val.uint16 : 0x0000;

		fprintf(stderr, "Product ID %04x:%04x:%04x\n", vendor, product, version);

		if (vendor == 0x1310 && product == 0x0100 && version == 0x0104) {
			fprintf(stderr, "Enabling GCT media payload workaround\n");
			if (flags)
				*flags |= NONSPECAUDIO;
		}

		next = seq->next;
		free(seq);
		sdp_record_free(rec);
	}

done:
	sdp_close(sess);
	return 0;
}

// Connecting on PSM 25
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

// Prepare packet headers
static void init_request(struct avdtp_header * header, int request_id)
{
	static int transaction = 0;

	header->packet_type = PACKET_TYPE_SINGLE;
	header->message_type = MESSAGE_TYPE_COMMAND;
	header->transaction_label = transaction;
	header->signal_id = request_id;

	// clear rfa bits
	header->rfa0 = 0;

	transaction = (transaction + 1) & 0xf;
}

static void init_response(struct avdtp_header * header, int response_type)
{
	// leave signal_id and transaction label since we are reusing the request
	header->packet_type = PACKET_TYPE_SINGLE;
	header->message_type = response_type;

	// clear rfa bits
	header->rfa0 = 0;
}

// monitor the control connection for pause/play signals from headset
// note this signaling is in the avdtp core; avrcp signaling is different
static void *listen_thread(void *init_data) 
{
	int size;
	struct stream_cmd cmd;
	printf("Listen thread running\n");
	while(!stop_writing) {
		size = read(cmdfd, &cmd, sizeof(cmd));
		if(size == sizeof(cmd)) {
			printf("received signal %d from set\n", cmd.header.signal_id);
			if(cmd.header.signal_id == AVDTP_SUSPEND) {
				pause_writing = 1;
			} else if(cmd.header.signal_id == AVDTP_START) {
				pause_writing = 0;
			} else {
				printf("unexpected headset directive %d\n", cmd.header.signal_id);
			}
			// ack the command regardless
			// take a shortcut and reuse the command struct (knock one byte off length)
			init_response(&cmd.header, MESSAGE_TYPE_ACCEPT);
			if (write(cmdfd, &cmd, sizeof(cmd)-1) != sizeof(cmd)-1) {
				fprintf(stderr, "Couldn't ack %d\n", cmd.header.signal_id);
			}
		}
		else
		{
			printf("error while receiving %d\n", size);
		}
	}
	pthread_exit(NULL);
	return NULL;
}

// Analyse the SEIDs the sink has sent to us
static int process_seid(int s, struct acp_seid_info * get_seid_resp, unsigned short *psm)
{
	int v, size;
	int seid = get_seid_resp->acp_seid;
	struct getcap_req put_req;
	struct getcap_resp cap_resp;
	struct set_config s_config;
	struct set_config_resp s_resp;
	struct stream_cmd open_stream;
	struct open_stream_rsp open_resp;
	fprintf(stderr, "SEID = %d\n", seid);

	memset(&put_req, 0, sizeof(put_req));
	init_request(&put_req.header, AVDTP_GET_CAPABILITIES);
	put_req.acp_seid = seid;

	if (write(s, &put_req, sizeof(put_req)) != sizeof(put_req)) {
		fprintf(stderr, "Couldn't request capabilities for SEID = %d\n", seid);
		return (-1);
	}
	else fprintf(stderr, "Requested Capabilities for SEID = %d\n",seid);
	if (read(s, &cap_resp, sizeof(cap_resp)) < sizeof(cap_resp) || 
			cap_resp.header.message_type == MESSAGE_TYPE_REJECT ||
			cap_resp.media_type != AUDIO_MEDIA_TYPE) {
		fprintf(stderr, "Didn't receive SBC codec parameters (first) for SEID = %d\n", seid);
		return (-1);
	}
	if (cap_resp.media_codec_type != SBC_MEDIA_CODEC_TYPE) {
		if(cap_resp.media_codec_type == MPEG12_MEDIA_CODEC_TYPE) {
			fprintf(stderr, "mpeg decoder found: layer3=%d channel_mode=%x frequency=%x bitrate0=%x bitrate1=%x\n",
				cap_resp.codec_elements.mpeg12_elements.layer3,
				cap_resp.codec_elements.mpeg12_elements.channel_mode,
				cap_resp.codec_elements.mpeg12_elements.frequency,
				cap_resp.codec_elements.mpeg12_elements.bitrate0,
				cap_resp.codec_elements.mpeg12_elements.bitrate1);
		} else {
			fprintf(stderr, "no SBC decoder here: media_codec_type is %d not %d for SEID = %d\n", 
				cap_resp.media_codec_type, SBC_MEDIA_CODEC_TYPE, seid);
		}
		return (-1);
	}

	fprintf(stderr, "Got capabilities response\n");

	memset(&s_config, 0, sizeof(s_config));
	init_request(&s_config.header, AVDTP_SET_CONFIGURATION);
	s_config.serv_cap = MEDIA_TRANSPORT_CATEGORY;
	s_config.acp_seid = seid;
	s_config.int_seid = 1;	// how should I choose the int_seid??
	s_config.cap_type = MEDIA_CODEC;
	s_config.length = 6;
	s_config.media_type = AUDIO_MEDIA_TYPE;
	s_config.media_codec_type = SBC_MEDIA_CODEC_TYPE;

	switch(sbc.channels) {
	case 1:
		v = 8;
		break;
	case 2:
	default:
		v = 2;
		break;
	}
	s_config.codec_elements.sbc_elements.channel_mode = v;

	switch(sbc.rate) {
	case 16000:
		v = 8;
		break;
	case 32000:
		v = 4;
		break;
	case 48000:
		v = 1;
		break;
	case 44100:
	default:
		v = 2; 
		break;
	}
	s_config.codec_elements.sbc_elements.frequency = v;
	s_config.codec_elements.sbc_elements.allocation_method = 1 << 1;

	switch(sbc.subbands) {
	case 4:
		v = 2;
		break;
	case 8:
	default:
		v = 1;
		break;
	}
	s_config.codec_elements.sbc_elements.subbands = v;

	switch(sbc.blocks) {
	case 4:
		v = 8;
		break;
	case 8:
		v = 4;
		break;
	case 12:
		v = 2;
		break;
	case 16:
	default:
		v = 1;
		break;
	}
	s_config.codec_elements.sbc_elements.block_length = v;
/*
  int_seid was 1 before
s_config was set from sbc_info before:
        s_config.codec_elements.sbc_elements.channel_mode = 8 >> sbc_info.channel_mode;
        s_config.codec_elements.sbc_elements.frequency = 8 >> sbc_info.sampling_frequency;
        s_config.codec_elements.sbc_elements.allocation_method = 1 << sbc_info.allocation_method;
        s_config.codec_elements.sbc_elements.subbands = 2 >> sbc_info.subbands;
        s_config.codec_elements.sbc_elements.block_length = 8 >> sbc_info.blocks;
 */
	s_config.codec_elements.sbc_elements.min_bitpool = cap_resp.codec_elements.sbc_elements.min_bitpool;
	s_config.codec_elements.sbc_elements.max_bitpool = cap_resp.codec_elements.sbc_elements.max_bitpool;

        //dump_packet(&s_config.codec_elements.sbc_elements, sizeof(s_config.codec_elements.sbc_elements)); //exit(0);

	if (!(cap_resp.codec_elements.sbc_elements.channel_mode & s_config.codec_elements.sbc_elements.channel_mode))
		fprintf(stderr, "headset does not support this channel mode\n");

	if (!(cap_resp.codec_elements.sbc_elements.frequency & s_config.codec_elements.sbc_elements.frequency))
		fprintf(stderr, "headset does not support this frequency\n");

	if (!(cap_resp.codec_elements.sbc_elements.allocation_method & s_config.codec_elements.sbc_elements.allocation_method))
		fprintf(stderr, "headset does not support this allocation_method\n");

	if (!(cap_resp.codec_elements.sbc_elements.subbands & s_config.codec_elements.sbc_elements.subbands))
		fprintf(stderr, "headset does not support this subbands setting\n");

	if (write(s, &s_config, sizeof(s_config)) != sizeof(s_config)) {
		fprintf(stderr, "couldn't set config seid = %d\n", seid);
		return (-1);
	}

	fprintf(stderr, "Sent set configurations command\n");
	
	size = read(s, &s_resp, sizeof(s_resp));
	if (size == sizeof(s_resp) - 2) {
	//if(size>0){
		fprintf(stderr, "Set configurations command accepted\n");
	} else {
		fprintf(stderr, "Set configurations command rejected\n");
		//return (-1);
	}
	
	memset(&open_stream, 0, sizeof(open_stream));
	init_request(&open_stream.header, AVDTP_OPEN);
	open_stream.acp_seid = seid;

	if (write(s, &open_stream, sizeof(open_stream)) != sizeof(open_stream)) {
		fprintf(stderr, "Couldn't open stream SEID = %d\n", seid);
		return (-1);
	}

	fprintf(stderr, "Sent open stream command\n");

	if (read(s, &open_resp, sizeof(open_resp)) < sizeof(open_resp) - 1 ||
			open_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		fprintf(stderr, "Didn't receive open response confirm for SEID = %d\n", seid);
		return (-1);
	}

	fprintf(stderr, "Got open stream confirm\n");

	*psm = 25;
	return 0;

}

int main(int argc, char *argv[])
{
	int timerset = 0;
	struct itimerval itimer;
	struct sigaction sa;
	struct sepd_req put_req;
	struct sepd_resp get_resp;
	struct stream_cmd start_stream;
	struct start_stream_rsp start_resp;
	struct media_packet_header packet_header;
	struct media_payload_header payload_header;
	struct stream_cmd close_stream;
	struct close_stream_rsp close_resp;
	struct sbc_frame_header sbc_info;

	bdaddr_t src, dst;
	unsigned short psm_cmd, psm_stream;
	unsigned long flags = 0;
	time_t timestamp;
	uint16_t mtu = 0, seq_num;
	int fd;
	int i;
	int format;
	int size;

	int fork = 0;
	int rate = 44100;
	int channels = 2;
	int little = 0;
	int pthreads = 1;
	int notimer = 0;
	int seid, last_seid_index;
	char *addrstr;
	char *filename;

	struct au_header *au_hdr;
      	unsigned char buf2[2048];
	unsigned long sleeptime = 0;
	int len, len2, count = 0;

	int size2;
	void *retval;
	int written;

#ifdef FORCE_LITTLE
	format = AFMT_S16_LE;
#else
	format = AFMT_S16_BE;
#endif

	bacpy(&src, BDADDR_ANY);

	// process command line
	while((i = getopt(argc, argv, "itpnvfdmlsr:")) >= 0) {
		switch(i) {
		case 't':
			thrifty++;
			break;
		case 'i':
			pthreads = 0;
			break;
		case 'p':
			pthreads = 1;
			break;
		case 'n':
			notimer = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'f':
			fork = 1;
			break;
		case 'd':
			raw = 1;
			break;
		case 'm':
			channels = 1;
			raw = 1;
			break;
		case 'l':
			// todo: reverse byte order before every sbc_encode if set
			little = 1;
			raw = 1;
			format=AFMT_S16_LE;
			break;
		case 's':
			livestream = 1;
			break;
		case 'r':
			if(!optarg || !(rate = atoi(optarg))) {
				usage();
				exit(1);
			}
			raw = 1;
			break;
		case 'h':
		case '?':
		case ':':
		default:
			usage();
			exit((i == 'h')?0:1);
		}
	}
	
	switch (argc - optind) {
	case 2:
		addrstr = argv[optind];
		filename = argv[optind+1];
		break;

	case 1:
		addrstr = argv[optind];
		filename = "-";
		break;

	default:
		usage();
		exit(-1);
	}
                                                                                
	if(sbc_init(&sbc, SBC_NULL)==-EIO) //SBC initialization failure
		exit(-1);
		
	sbc.subbands = 8;
	sbc.blocks = 16;
	sbc.bitpool = 32;

	switch(thrifty) {
	case 5:
		sbc.bitpool -= 12;
	case 4:
		sbc.blocks -= 4;
		sbc.bitpool -= 2;
	case 3:
		sbc.blocks -= 4;
		sbc.bitpool -= 2;
	case 2:
		sbc.blocks -= 4;
		sbc.bitpool -= 2;
	case 1:
		//sbc.subbands -= 4;
		sbc.bitpool -= 2;
	}

	fprintf(stderr, "subbands = %d blocks = %d bitpool = %d\n", sbc.subbands, sbc.blocks, sbc.bitpool);

	if(!strcmp(filename,"-")) {
		fd = 0;
	} else {
		fd = open(filename, 0);
		if (fd < 0) {
			fprintf(stderr, "couldn't open %s\n", filename);
			exit(-1);
		}
	}

	if(raw) {
		sbc.rate = rate;
		sbc.channels = channels;

		if(ioctl(fd,SNDCTL_DSP_SETFMT,&format)==-1) {
			fprintf(stderr, "cannot set format on input %s\n", filename);
		}
		
		if(ioctl(fd,SNDCTL_DSP_CHANNELS,&channels)==-1) {
			fprintf(stderr, "cannot set channels on input %s\n", filename);
		}
		
		if(ioctl(fd,SNDCTL_DSP_SPEED,&rate)==-1) {
			fprintf(stderr, "cannot set rate on input %s\n", filename);
		}

		size2 = __read(fd, buf2, sizeof(buf2));
	} else {
		len = __read(fd, buf2, sizeof(buf2));
		fprintf(stderr, "len=%d\n",len);
		if (len < sizeof(*au_hdr)) {
			if (fd > fileno(stderr))
				fprintf(stderr, "Can't read header from file %s: %s\n",
					filename, strerror(errno));
			else
				perror("Can't read audio header");
                	exit(-1);
		}
		
		au_hdr = (struct au_header *) buf2;
		
		if (au_hdr->magic != AU_MAGIC ||
		    BE_INT(au_hdr->hdr_size) > 128 ||
		    BE_INT(au_hdr->hdr_size) < 24 ||
		    BE_INT(au_hdr->encoding) != AU_FMT_LIN16) {
			fprintf(stderr, "Data is not in Sun/NeXT audio S16_BE format\n");
			close(fd);
			exit(-1);
		}
		sbc.rate = BE_INT(au_hdr->sample_rate);
		sbc.channels = BE_INT(au_hdr->channels);
		count = BE_INT(au_hdr->data_size);
		size2 = len - BE_INT(au_hdr->hdr_size);
		fprintf(stderr, "Header size=%d\n",BE_INT(au_hdr->hdr_size));
		memmove(buf2, buf2 + BE_INT(au_hdr->hdr_size), size2);
	}

        fprintf(stderr, "Sample Rate:%d\n", sbc.rate);
        fprintf(stderr, "Channels:%d\n", sbc.channels);

	memset(&sbc_info,0,sizeof(sbc_info)); 
	if (size2 < sizeof(buf2)) {
        	len = __read(fd, buf2 + size2, sizeof(buf2) - size2);                           
		if (len < 0) {
                	perror("Can't read audio data");
                        exit(-1);
		}                                                                               
		size2 += len;
        }
        len = sbc_encode(&sbc, buf2, size2);//do the encoding
	sleeptime = sbc.duration;
	sbc_info.blocks = sbc.blocks;
	sbc_info.subbands = sbc.subbands;

        if (len < size2) {
        	memmove(buf2, buf2 + len, size2 - len);                                 
		size2 -= len;		
	}

	fprintf(stderr, "Using address: %s\n", addrstr);
	str2ba(addrstr, &dst);

	if (detect_a2dp(&src, &dst, &psm_cmd, &flags) < 0) {
		fprintf(stderr, "could not find A2DP services on device %s\n", addrstr);
		exit(-1);
	}
	else fprintf(stderr, "Found A2DP Sink at the destination\n");

	/* setup sigterm handler. we must make sure to do a clean disconnect */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

#if 0
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
#endif

	sa.sa_handler = sig_alrm;
	//sa.sa_flags = SA_NODEFER;
	sigaction(SIGALRM, &sa, NULL);

	psm_cmd=25;	
	cmdfd = do_connect(&src, &dst, psm_cmd, NULL);
	if (cmdfd < 0) {
		fprintf(stderr, "cannot open psm_cmd = %d\n", psm_cmd);
		exit(-1);
	}
	// avdt_discover_req
	memset(&put_req, 0, sizeof(put_req));
	init_request(&put_req.header, AVDTP_DISCOVER);

	if (write(cmdfd, &put_req, sizeof(put_req)) != sizeof(put_req)) {
		fprintf(stderr, "couldn't send avdtp_discover\n");
		close(cmdfd);
		exit(-1);
	}
	else fprintf(stderr, "Sent the Stream End Point Discovery Command\n");
	size = read(cmdfd, &get_resp, sizeof(get_resp));
	if (size == 2 && get_resp.header.message_type == 0 && get_resp.header.packet_type == 0) 
		// Try again if this fails once (BlueAnt headset)
		size = read(cmdfd, &get_resp, sizeof(get_resp));
	if (size < sizeof(get_resp) - MAX_ADDITIONAL_CODEC_OCTETS) {
		fprintf(stderr, "couldn't get avdtp_discover (only %d bytes read)\n", size);
		close(cmdfd);
		exit(-1);
	}
	else fprintf(stderr, "Got a Stream End Point Discovery Response\n");
	seid = -1;
	last_seid_index = MAX_ADDITIONAL_CODEC - ((sizeof(get_resp)-size)/sizeof(struct acp_seid_info));

	fprintf(stderr, "received %d capabilities\n", last_seid_index + 1);

	for(i=last_seid_index; i >= 0; i--) {
		if (process_seid(cmdfd, &get_resp.infos[i], &psm_stream) == 0) {
			seid = get_resp.infos[i].acp_seid;
			break;
		}
	}

	if(seid == -1) {
		//We have not found the seid that we want
		fprintf(stderr, "couldn't locate the correct seid\n");
		exit(-1);
	}

	// open the stream

#if 0
	// try to make the mtu short so the headset will accept shorter frames
	// the iTech etc ignore this for omtu
	if(livestream)
		mtu = 504;
#endif

	streamfd = do_connect(&src, &dst, psm_stream, &mtu);
	if (streamfd < 0) {
		fprintf(stderr, "cannot open psm_stream = %d\n", psm_stream);
		exit(-1);
	}

	// start the stream

	memset(&start_stream, 0, sizeof(start_stream));
	init_request(&start_stream.header, AVDTP_START);
	start_stream.acp_seid = seid;

	if (write(cmdfd, &start_stream, sizeof(start_stream)) != sizeof(start_stream)) {
		fprintf(stderr, "couldn't send start_stream\n");
		close(streamfd);
		close(cmdfd);
		exit(-1);
	}

	fprintf(stderr, "Sent stream start\n");

	if (read(cmdfd, &start_resp, sizeof(start_resp)) < sizeof(start_resp) - 2 ||start_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		fprintf(stderr, "didn't receive start_resp confirm for seid = %d\n", seid);
		close(streamfd);
		close(cmdfd);
		return (-1);
	}

	fprintf(stderr, "Got start stream confirm\n");

	if (mtu > BUFS)
		mtu = BUFS;

	seq_num = 1;

	memset(&payload_header, 0, sizeof(payload_header));

	timestamp = 0;

	while (!stop_reading) {

		// a2dp headers: avdtp p.45
		memset(&packet_header, 0, sizeof(packet_header));
		packet_header.v = 2;
		packet_header.pt = 1;
		packet_header.sequence_number = htons(seq_num);
		packet_header.timestamp = htonl(timestamp);
		packet_header.ssrc = htonl(1);
		timestamp += (sbc_info.blocks + 1)*4 * (sbc_info.subbands + 1)*4;

		memcpy(buf[ring_in], &packet_header, sizeof(packet_header));
		psize[ring_in] = sizeof(packet_header);

		// framing a2dp p.23
		payload_header.frame_count = 0;

		if (flags & NONSPECAUDIO) {
			/* BEGIN: NONSPECAUDIO == TRUE */

			buf[ring_in][12] = 0xff;
			buf[ring_in][13] = 0xff;

			memcpy(buf[ring_in] + MEDIA_PACKET_HEADER_LENGTH, sbc.data, sbc.len);
			len2 = __read(fd, buf2 + size2, len);
			if(len2 == 0)
				stop_reading = 1;
			if(len2 < 0) {
				perror("Can't Read Audio Data");
				break;
			}

			// framing, fragmenting, a2dp headers: avdtp p.45 and a2dp spec p.23
			written = write(streamfd, buf[ring_in], size + sizeof(sbc_info) + MEDIA_PACKET_HEADER_LENGTH);
			if(written == -1) {
				perror("write failed");
				break;
			}
			size2 += len;
			len = sbc_encode(&sbc, buf2, size2);
			sleeptime += sbc.duration;
			sbc_info.blocks = sbc.blocks;
			sbc_info.subbands = sbc.subbands;

			if (len < size2)
				memmove(buf2, buf2 + len, size2 - len);
			size2 -= len;

			/* END: NONSPECAUDIO == TRUE */
		} else {
			/* BEGIN: NONSPECAUDIO == FALSE */

			// make room for the payload header but don't copy it yet (count up frames first)
			psize[ring_in] += sizeof(payload_header);	
			do {
				payload_header.frame_count++;
				memcpy(buf[ring_in] + psize[ring_in], sbc.data, sbc.len);
				psize[ring_in] += sbc.len;
				
				do
					len2= __read(fd, buf2 + size2, len);
				while(len2 == -1 && errno == EINTR && !stop_reading);
				
                        	if (len2 == 0)
                                	stop_reading = 1;
                                                                                                 
                        	if (len2 < 0) {
                                	perror("Can't read audio data2");
                               	 	break;
                        	}       	                                                                  
                        	size2 += len;

				if(size2 > 0) {
					len = sbc_encode(&sbc, buf2, size2);
					sleeptime += sbc.duration;
					sbc_info.blocks = sbc.blocks;
					sbc_info.subbands = sbc.subbands;
					if (len < size2)
						memmove(buf2, buf2 + len, size2 - len);                                         
					size2 -= len;
				}

			} while (!stop_reading && psize[ring_in] + sbc.len < mtu);

			memcpy(buf[ring_in] + sizeof(packet_header), &payload_header, sizeof(payload_header));

			packetticks = compute_ticks(sleeptime);

			if(notimer) {
				send_packet();
			} else if(!timerset) {
				timerset = 1;

				// using either itimer or pthreads
				if(pthreads) {
					unsigned long rate = TICKS;
					rtcfd = open("/dev/rtc", O_RDONLY);
					if(rtcfd < 0) {
						perror("/dev/rtc open");
						exit(1);
					}
					if(ioctl(rtcfd, RTC_IRQP_SET, rate) == -1) {
						fprintf(stderr, "Couldn't set rtc rate. Try\n rmmod genrtc ; modprobe rtc ; echo %ld > /proc/sys/dev/rtc/max-user-freq\n", 
						       rate);
						perror("rtc rate ioctl");
						exit(1);
					}
					if(ioctl(rtcfd, RTC_PIE_ON, 0) == -1) {
						perror("rtc enable ioctl");
						exit(1);
					}
					pthread_create(&transmit_pid, NULL, transmit_thread, NULL);
					pthread_create(&listen_pid, NULL, listen_thread, NULL);
				} else {
					itimer.it_interval.tv_sec = itimer.it_value.tv_sec = 0;
					itimer.it_interval.tv_usec = itimer.it_value.tv_usec = (sleeptime*(87))/100;
					if(setitimer(ITIMER_REAL, &itimer, NULL)) fprintf(stderr, "couldn't setitimer\n");
				}
			}
			sleeptime = 0;

			// pause if the ring buffer is full
			while((ring_out + 1) % PACKETBUF == ring_in) usleep(1000);

			// advance the ring in buffer
			ring_in = (ring_in + 1) % PACKETBUF;

			/* END: NONSPECAUDIO == FALSE */
		}

		seq_num++;
	}

	// finish the stream before exiting
	while(!notimer && !stop_writing && ring_out != ring_in) {
		usleep(1000);
	}
	
	fprintf(stderr, "ending stream\n");
	stop_writing = 1;

	// finished reading audio from source
	close(fd);
	sbc_finish(&sbc);

	fprintf(stderr, "Sent %d packets\n", seq_num);

	if(pthreads) {
		fprintf(stderr, "joining x thread\n");
		pthread_join(transmit_pid, &retval);
		// have to stop the listener thread because it's blocked on i/o
		fprintf(stderr, "stopping r thread\n");
		pthread_kill(listen_pid, SIGINT);
		fprintf(stderr, "closing rtc\n");
		close(rtcfd);
	}

	// signal the stream close

	memset(&close_stream, 0, sizeof(close_stream));
	memset(&close_resp, 0, sizeof(close_resp));

	// the stream-close used to make the iTech headset lock up and require it to be powercycled
	// should be tested again now that we drain the queue properly

	init_request(&close_stream.header, AVDTP_CLOSE);
	close_stream.acp_seid = seid;

#if 1
	if (write(cmdfd, &close_stream, sizeof(close_stream)) != sizeof(close_stream)) {
		fprintf(stderr, "couldn't send close_stream\n");
		close(streamfd);
		close(cmdfd);
		exit(-1);
	}
	fprintf(stderr, "Sent stream-close\n");

	if (read(cmdfd, &close_resp, sizeof(close_resp)) < sizeof(close_resp) - 1 ||
			close_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		fprintf(stderr, "didn't receive close_resp confirm for seid = %d\n", seid);
		close(streamfd);
		close(cmdfd);
		return (-1);
	}

	fprintf(stderr, "Got close stream confirm\n");
#endif

	fprintf(stderr, "closing stream\n");
	close(streamfd);
	fprintf(stderr, "closing control connection\n\n");
	close(cmdfd);

	return 0;
}
