/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>
#include <alsa/timer.h>

#include <pthread.h>

#include <netinet/in.h>

#include "../sbc/sbc.h"
#include "../a2dp.h"

#define NONSPECAUDIO 1
#define BUFS 1024

#define min(X, Y)  ((X) < (Y) ? (X) : (Y))
#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
//#define DBG(D...)

struct sigaction        actions;

static void a2dp_init(void) __attribute__ ((constructor));
static void a2dp_exit(void) __attribute__ ((destructor));

static void change_endian( void *buf, int size)
{
	int i;
	char c;
	char *ptr;

	ptr = buf;
	for(i = 0; i < size; i += 2) {
		c = ptr[i];
		ptr[i] = ptr[i+1];
		ptr[i+1] = c;
	}
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

// Analyse the SEIDs the sink has sent to us
static int process_seid(int s, struct acp_seid_info * get_seid_resp, unsigned short *psm, sbc_t *sbc)
{
	int v, size;
	int seid = get_seid_resp->acp_seid;
	struct getcap_req put_req;
	struct getcap_resp cap_resp;
	struct set_config s_config;
	struct set_config_resp s_resp;
	struct stream_cmd open_stream;
	struct open_stream_rsp open_resp;
	DBG("SEID = %d", seid);

	memset(&put_req, 0, sizeof(put_req));
	init_request(&put_req.header, AVDTP_GET_CAPABILITIES);
	put_req.acp_seid = seid;

	if (write(s, &put_req, sizeof(put_req)) != sizeof(put_req))
	{
		DBG("Couldn't request capabilities for SEID = %d", seid);
		return (-1);
	}
	else {
		DBG("Requested Capabilities for SEID = %d",seid);
	}
	if (read(s, &cap_resp, sizeof(cap_resp)) < sizeof(cap_resp) ||
			cap_resp.header.message_type == MESSAGE_TYPE_REJECT ||
			cap_resp.media_type != AUDIO_MEDIA_TYPE ||
			cap_resp.media_codec_type != SBC_MEDIA_CODEC_TYPE) {
		DBG("Didn't receive SBC codec parameters (first) for SEID = %d", seid);
		return (-1);
	}

	DBG("Got capabilities response");

	memset(&s_config, 0, sizeof(s_config));
	init_request(&s_config.header, AVDTP_SET_CONFIGURATION);
	s_config.serv_cap = MEDIA_TRANSPORT_CATEGORY;
	s_config.acp_seid = seid;
	s_config.int_seid = 1;	// how should I choose the int_seid??
	s_config.cap_type = MEDIA_CODEC;
	s_config.length = 6;
	s_config.media_type = AUDIO_MEDIA_TYPE;
	s_config.media_codec_type = SBC_MEDIA_CODEC_TYPE;

	switch(sbc->channels) {
	case 1:
		v = 8;
		break;
	case 2:
	default:
		v = 2;
		break;
	}
	s_config.codec_elements.sbc_elements.channel_mode = v;

	switch(sbc->rate) {
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

	switch(sbc->subbands) {
	case 4:
		v = 2;
		break;
	case 8:
	default:
		v = 1;
		break;
	}
	s_config.codec_elements.sbc_elements.subbands = v;

	switch(sbc->blocks) {
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
	s_config.codec_elements.sbc_elements.min_bitpool = cap_resp.codec_elements.sbc_elements.min_bitpool;
	s_config.codec_elements.sbc_elements.max_bitpool = cap_resp.codec_elements.sbc_elements.max_bitpool;

	if (!(cap_resp.codec_elements.sbc_elements.channel_mode & s_config.codec_elements.sbc_elements.channel_mode)) {
		DBG("headset does not support this channel mode");
	}

	if (!(cap_resp.codec_elements.sbc_elements.frequency & s_config.codec_elements.sbc_elements.frequency)) {
		DBG("headset does not support this frequency");
	}

	if (!(cap_resp.codec_elements.sbc_elements.allocation_method & s_config.codec_elements.sbc_elements.allocation_method)) {
		DBG("headset does not support this allocation_method");
	}

	if (!(cap_resp.codec_elements.sbc_elements.subbands & s_config.codec_elements.sbc_elements.subbands)) {
		DBG("headset does not support this subbands setting");
	}

	if (write(s, &s_config, sizeof(s_config)) != sizeof(s_config)) {
		DBG("couldn't set config seid = %d", seid);
		return (-1);
	}

	DBG("Sent set configurations command");
	
	size = read(s, &s_resp, sizeof(s_resp));
	if (size == sizeof(s_resp) - 2) {
		DBG("Set configurations command accepted");
	} else {
		DBG("Set configurations command rejected");
	}
	
	memset(&open_stream, 0, sizeof(open_stream));
	init_request(&open_stream.header, AVDTP_OPEN);
	open_stream.acp_seid = seid;

	if (write(s, &open_stream, sizeof(open_stream)) != sizeof(open_stream)) {
		DBG("Couldn't open stream SEID = %d", seid);
		return (-1);
	}

	DBG("Sent open stream command");

	if (read(s, &open_resp, sizeof(open_resp)) < sizeof(open_resp) - 1 ||
			open_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		DBG("Didn't receive open response confirm for SEID = %d", seid);
		return (-1);
	}

	DBG("Got open stream confirm");

	*psm = 25;
	return 0;
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
	int tries;

	tries = 0;
	while(!(sess = sdp_connect(src, dst, SDP_RETRY_IF_BUSY)))
	{
		DBG("retrying sdp connect: %s", strerror(errno));
		sleep(1);
		if(++tries > 10)
		{
			break;
		}
	}
	if (!sess)
	{
		DBG( "Warning: failed to connect to SDP server: %s", strerror(errno));
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

	if (err)
	{
		DBG( "Service Search failed: %s", strerror(errno));
		sdp_close(sess);
		return -1;
	}

	for (; seq; seq = next)
	{
		sdp_record_t *rec = (sdp_record_t *) seq->data;

		DBG( "Found A2DP Sink");
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

	for (; seq; seq = next)
	{
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		uint16_t vendor, product, version;

		pdlist = sdp_data_get(rec, 0x0201);
		vendor = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, 0x0202);
		product = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, 0x0203);
		version = pdlist ? pdlist->val.uint16 : 0x0000;

		DBG( "Product ID %04x:%04x:%04x", vendor, product, version);

		if (vendor == 0x1310 && product == 0x0100 && version == 0x0104) {
			DBG( "Enabling GCT media payload workaround");
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

// open an L2CAP connection on psm to the headset at dst
// called with psm 25 for the command connection and later with a discovered psm for the stream
static int do_connect(bdaddr_t *src, bdaddr_t *dst, unsigned short psm, uint16_t *mtu)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk;
	unsigned int opt;
	int tries;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		DBG( "Can't create socket. (errno=%d:%s)", errno, strerror(errno));
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);
	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DBG( "Can't bind socket. (errno=%d:%s)", errno, strerror(errno));
		return -1;
	}

	/* Get default options */
	opt = sizeof(opts);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		DBG( "Can't get default L2CAP options. (errno=%d:%s)", errno, strerror(errno));
		return -1;
	}

	/* Set new options */
	if(mtu && *mtu) {
		opts.omtu = *mtu;
		//opts.imtu = *mtu;
	}
	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, opt) < 0) {
		DBG( "Can't set L2CAP options. (errno=%d:%s)", errno, strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(psm);

	tries = 0;
	while (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DBG("Can't connect to %s on psm %d. (errono=%d:%s)",
				batostr(&addr.l2_bdaddr), psm, errno, strerror(errno));
		sleep(1);
		++tries;
		if(++tries > 10) {
			close(sk);
			return -1;
		}
	}
	opt = sizeof(opts);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		DBG( "Can't get L2CAP options. (errno=%d:%s)", errno, strerror(errno));
		close(sk);
		return -1;
	}

	DBG( "Connected [imtu %d, omtu %d, flush_to %d]",
					opts.imtu, opts.omtu, opts.flush_to);

	if (mtu)
		*mtu = opts.omtu;

	return sk;
}

static int connect_stream(bdaddr_t *src, bdaddr_t *dst, int *cmdfd_return, sbc_t *sbc, int* seid_return) {
	int cmdfd;
	struct getcap_req put_req;
	struct sepd_resp get_resp;
	struct stream_cmd start_stream;
	struct start_stream_rsp start_resp;
	int seid, last_seid_index;
	int size;
	int i;
	unsigned short psm_cmd,psm_stream;
	unsigned long flags = 0;
	static int streamfd;
	uint16_t mtu = 0;
	int tries;

	DBG( "Using address: %s", batostr(dst));

	if (detect_a2dp(src, dst, &psm_cmd, &flags) < 0) {
		DBG( "could not find A2DP services on device %s", batostr(dst));
		exit(-1);
	}
	else {
		DBG( "Found A2DP Sink at the destination");
	}


	psm_cmd=25;	
	cmdfd = do_connect(src, dst, psm_cmd, NULL);
	if (cmdfd < 0) {
		DBG( "cannot open psm_cmd = %d", psm_cmd);
		exit(-1);
	}

	// avdt_discover_req
	memset(&put_req, 0, sizeof(put_req));
	init_request(&put_req.header, AVDTP_DISCOVER);

	if (write(cmdfd, &put_req, sizeof(put_req)) != sizeof(put_req)) {
		DBG("couldn't send avdtp_discover");
		close(cmdfd);
		exit(-1);
	}
	else {
		DBG("Sent the Stream End Point Discovery Command");
	}
	tries = 0;
	while((size = read(cmdfd, &get_resp, sizeof(get_resp))) < 0) {
		DBG("retrying discover response read...");
		sleep(1);
		if(++tries > 10) {
			break;
		}
	}
	if (size == 2 && get_resp.header.message_type == 0 && get_resp.header.packet_type == 0) {
		// Try again if this fails once (BlueAnt headset)
		DBG("Discovery Response is the Wrong Size, Trying Read Again");
		size = read(cmdfd, &get_resp, sizeof(get_resp));
	}
	if (size < sizeof(get_resp) - MAX_ADDITIONAL_CODEC_OCTETS) {
		DBG("couldn't get avdtp_discover");
		close(cmdfd);
		exit(-1);
	}
	else {
		DBG("Got a Stream End Point Discovery Response");
	}
	seid = -1;
	last_seid_index = MAX_ADDITIONAL_CODEC - ((sizeof(get_resp)-size)/sizeof(struct acp_seid_info));

	DBG("received %d capabilities", last_seid_index + 1);

	for(i=0; i <= last_seid_index; i++) {
		if (process_seid(cmdfd, &get_resp.infos[i], &psm_stream, sbc) == 0) {
			seid = get_resp.infos[i].acp_seid;
			break;
		}
	}

	if(seid == -1) {
		//We have not found the seid that we want
		DBG("couldn't locate the correct seid");
		exit(-1);
	}

	// open the stream

	streamfd = do_connect(src, dst, psm_stream, &mtu);
	if (streamfd < 0) {
		DBG("cannot open psm_stream = %d", psm_stream);
		exit(-1);
	}

	// start the stream

	memset(&start_stream, 0, sizeof(start_stream));
	init_request(&start_stream.header, AVDTP_START);
	start_stream.acp_seid = seid;

	if (write(cmdfd, &start_stream, sizeof(start_stream)) != sizeof(start_stream)) {
		DBG("couldn't send start_stream");
		close(streamfd);
		close(cmdfd);
		exit(-1);
	}

	DBG("Sent stream start");

	if (read(cmdfd, &start_resp, sizeof(start_resp)) < sizeof(start_resp) - 2 ||start_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		DBG("didn't receive start_resp confirm for seid = %d", seid);
		close(streamfd);
		close(cmdfd);
		return (-1);
	}

	DBG("Got start stream confirm");
	
	*cmdfd_return = cmdfd;
	*seid_return = seid;
	return streamfd;
}

typedef struct snd_pcm_a2dp {
	snd_pcm_ioplug_t io;
	int refcnt;
	int timeout;
	unsigned long state;
	bdaddr_t src;
	bdaddr_t dst;
	int sk;
	int control_sk;
	int seid;
	sbc_t sbc;
	snd_pcm_sframes_t num;
	unsigned char buf[1024];
	unsigned int len;
	unsigned int frame_bytes;
	int use_rfcomm;

	char bufe[BUFS];
	int lenbufe;//=0;

	unsigned long nbytes;//=0;

	struct timeval tsend;

	time_t timestamp;//=0;
	uint16_t seq_num;//=1;
	int frame_count;//=0;

	// Used to control stream from headset
	int stop_writing;// = 0;
	int pause_writing;// = 0;
	pthread_t hListenThread;
} snd_pcm_a2dp_t;

static void inline a2dp_get(snd_pcm_a2dp_t *a2dp)
{
	a2dp->refcnt++;
	a2dp->timeout = 0;
}

static void inline a2dp_put(snd_pcm_a2dp_t *a2dp)
{
	a2dp->refcnt--;

	if (a2dp->refcnt <= 0)
		a2dp->timeout = 2;
}

static int a2dp_start(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 13;

	return 0;
}

static int a2dp_stop(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	DBG("Listen thread terminating");
	a2dp->stop_writing = 1;
	pthread_kill(a2dp->hListenThread, SIGALRM);
	pthread_join(a2dp->hListenThread, NULL);
	DBG("Listen thread terminated");

	a2dp->len = 0;

	DBG("OK");
	return 0;
}

static snd_pcm_sframes_t a2dp_pointer(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	return a2dp->num;
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
static void *listen_thread(void * param) 
{
	snd_pcm_a2dp_t* a2dp = (snd_pcm_a2dp_t*)param;

	printf("Listen thread running\n");

	// Set a timeout to close thread
	struct timeval t = { 5, 0 };
	setsockopt( a2dp->control_sk, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
	setsockopt( a2dp->control_sk, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));

	// Loop until end of writing
	while(!a2dp->stop_writing)
	{
		int size;
		struct stream_cmd cmd;
		printf("Awaiting command\n");
		size = read(a2dp->control_sk, &cmd, sizeof(cmd));
		if(size == sizeof(cmd))
		{
			printf("Received signal %d from set\n", cmd.header.signal_id);
			if(cmd.header.signal_id == AVDTP_SUSPEND)
			{
				a2dp->pause_writing = 1;
			}
			else if(cmd.header.signal_id == AVDTP_START)
			{
				a2dp->pause_writing = 0;
			}
			else
			{
				printf("Unexpected headset directive %d\n", cmd.header.signal_id);
			}
			// ack the command regardless
			// take a shortcut and reuse the command struct (knock one byte off length)
			init_response(&cmd.header, MESSAGE_TYPE_ACCEPT);
			if (write(a2dp->control_sk, &cmd, sizeof(cmd)-1) != sizeof(cmd)-1)
			{
				fprintf(stderr, "Couldn't ack %d\n", cmd.header.signal_id);
			}
		}
		else
		{
			if(errno!=EAGAIN)
				printf("Error while receiving %d (errno=%d:%s)\n", size, errno, strerror(errno));
			// Got end signal, leave
			if(errno==EINTR)
				break;
		}
	}

	printf("%s: ending perfeclty\n", __FUNCTION__);
	return NULL;
}

static void sleeptill(struct timeval *t, struct timeval *dt)
{
	struct timeval tc,dtc;
	struct timezone tz;
	int i;

   	i=gettimeofday(&tc,&tz);
	if timercmp(t, &tc, <){ // too late to wait
		timeradd(&tc, dt, t);
		return;
	}
	usleep(1); //sinchronize with usleep cycle
   	i=gettimeofday(&tc,&tz);
	timersub(t, &tc, &dtc);
	if (dtc.tv_sec==0){	timeradd(t, dt, t);}
	else {timeradd(&tc, dt, t);return; } //more than a second to sleep, possibly error
	if (dtc.tv_usec<=2000)  return; //too late to sleep
	usleep(dtc.tv_usec-2000); // wake up somewhere in the middle of 4ms
	return;
}

/*
// returns time to wait ie difference between tsend and current time
// if time has come, advances tsend
static int time_to_wait(struct timeval *tsend, struct timeval *dt)
{
	struct timeval tc,dtc,t2,dt2;
	struct timezone tz;
	int i;
	dt2.tv_sec=0;
	dt2.tv_usec=2000;// middle of 4ms
   	i=gettimeofday(&tc,&tz);

	timeradd(&tc, &dt2, &t2);
	
	if timercmp(tsend, &t2, <){ // time has come
		timeradd(tsend, dt, tsend);
		if timercmp(tsend, &tc, <)	timeradd(&tc, dt, tsend); //if tsend<tc; tsend=tc+dt
		return 0;
	}
	timersub(tsend, &tc, &dtc);
	return dtc.tv_usec;
}

// transfers around correct time postions
static snd_pcm_sframes_t a2dp_transfer(snd_pcm_ioplug_t *io,
			const snd_pcm_channel_area_t *areas,
			snd_pcm_uframes_t offset, snd_pcm_uframes_t size)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	char *buf;
	int len;
	struct media_packet_header packet_header;
	struct media_payload_header payload_header;
	int codesize,datatoread;
	unsigned long sleeptime;
	struct timeval dt;
	

	codesize=a2dp->sbc.subbands*a2dp->sbc.blocks*a2dp->sbc.channels*2; // size of data encoded by sbc_encode in one call
	datatoread=min(codesize,size*a2dp->frame_bytes); // amount of data to read
	buf = (char *) areas->addr + (areas->first + areas->step * offset) / 8;
    	if(a2dp->lenbufe<codesize && a2dp->lenbufe+datatoread<sizeof(a2dp->bufe)){ // if not enough data in bufe to encode and there is space in bufe
		memcpy(a2dp->bufe+a2dp->lenbufe,buf,datatoread);// we read data to bufe
		a2dp->lenbufe+=datatoread;
	}
	else{datatoread=0;}//nothing has been read

	if(a2dp->lenbufe>=codesize && a2dp->len + a2dp->sbc.len < 678){ // if enough data in bufe to encode and not enough frame to fill up mtu: encoding
		change_endian(a2dp->bufe,codesize); // changing the endianness
		len = sbc_encode(&(a2dp->sbc), a2dp->bufe, codesize); //encode
		memmove(a2dp->bufe, a2dp->bufe + len, a2dp->lenbufe - len); //shift the bufe                                 
		a2dp->lenbufe-=len;
		a2dp->nbytes+=len;
		sleeptime += a2dp->sbc.duration;
		if (len <= 0)
			return len;
		a2dp->frame_count++;
		memcpy(a2dp->buf + a2dp->len, a2dp->sbc.data, a2dp->sbc.len); // copy encoded frames into a2dp->buf
		a2dp->len+=a2dp->sbc.len;
		if (a2dp->state == BT_CONNECTED)
			a2dp->num += len / a2dp->frame_bytes; //update pointer
			a2dp->num %=io->buffer_size;
	}		

	if(a2dp->len + a2dp->sbc.len > 678){ // if packet is formed
		dt.tv_usec=1000000*a2dp->sbc.subbands*a2dp->sbc.blocks*a2dp->frame_count/io->rate; // time interval between transmitions
		dt.tv_sec=0;
		if(time_to_wait(&a2dp->tsend, &dt)==0){ // time to send data
			memset(&payload_header, 0, sizeof(payload_header)); // fill up the headers
			memset(&packet_header, 0, sizeof(packet_header)); //---
			payload_header.frame_count=a2dp->frame_count;
			packet_header.v = 2;
			packet_header.pt = 1;
			packet_header.sequence_number = htons(a2dp->seq_num);
			packet_header.timestamp = htonl(a2dp->timestamp);
			packet_header.ssrc = htonl(1);
			a2dp->timestamp += (a2dp->sbc.blocks + 1)*4 * (a2dp->sbc.subbands + 1)*4;
			memcpy(a2dp->buf, &packet_header, sizeof(packet_header)); //copy the headers to buf
			memcpy(a2dp->buf + sizeof(packet_header), &payload_header, sizeof(payload_header));//---
			write(a2dp->sk,a2dp->buf,a2dp->len); // sending the packet
			a2dp->len = sizeof(packet_header)+sizeof(payload_header); //inital position in buf, just after headers
			a2dp->frame_count=0;
			sleeptime=0;
			a2dp->seq_num++;
		}else{usleep(1);}
	}
	return datatoread / a2dp->frame_bytes;
}
*/
// also works but sleeps between transfers
static snd_pcm_sframes_t a2dp_transfer2(snd_pcm_ioplug_t *io,
			const snd_pcm_channel_area_t *areas,
			snd_pcm_uframes_t offset, snd_pcm_uframes_t size)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	char *buf;
	int len;
	struct media_packet_header packet_header;
	struct media_payload_header payload_header;
	int codesize,datatoread;
	unsigned long sleeptime=0;
	int written;
	struct timeval dt;
	struct timeval timeofday;
	gettimeofday(&timeofday, NULL);

	// Time reference
	static struct timeval staticcounter = {0,0};
	static int sbc_bps=0;
	if(staticcounter.tv_sec==0)
	{
		gettimeofday(&staticcounter, NULL);
	}

	struct timeval duration;
	timersub(&timeofday, &staticcounter, &duration);

	// Display bandwidth once per second
	if(duration.tv_sec>0)
	{
		printf("SBC Bandwidth = %d kbps [%d bps]\n", sbc_bps/1024, sbc_bps);
		// Reset static counter
		gettimeofday(&staticcounter, NULL);
		sbc_bps=0;
	}

	codesize=a2dp->sbc.subbands*a2dp->sbc.blocks*a2dp->sbc.channels*2;
	datatoread=min(codesize,size*a2dp->frame_bytes);

	/*
	DBG("(%2d%3d): %d + %d * %d (=%d)",
	    (timeofday.tv_sec      )%100,  // s
	    (timeofday.tv_usec/1000)%1000, // ms
	    (int)areas->first, (int)areas->step, offset, (areas->first + areas->step * offset));

	DBG("(%2d%3d): %d * %d * %d * 2 (=%d) x %d",
	    (timeofday.tv_sec      )%100,  // s
	    (timeofday.tv_usec/1000)%1000, // ms
	    a2dp->sbc.subbands, // 8
	    a2dp->sbc.blocks, // 16
	    a2dp->sbc.channels, // 2
	    codesize, // 512
	    datatoread); // 512
	*/
	buf = (char *) areas->addr + (areas->first + areas->step * offset) / 8;
   	if(a2dp->lenbufe<codesize)
	{
		memcpy(a2dp->bufe+a2dp->lenbufe,buf,datatoread);
		a2dp->lenbufe+=datatoread;
	}  
	else{datatoread=0;}

	if(a2dp->lenbufe>=codesize)
	{
		//enough data to encode
		change_endian(a2dp->bufe,codesize); // changing the endianness
		len = sbc_encode(&(a2dp->sbc), a2dp->bufe, codesize); //encode
		memmove(a2dp->bufe, a2dp->bufe + len, a2dp->lenbufe - len); //shift the bufe                                 
		a2dp->lenbufe-=len;
		a2dp->nbytes+=len;
		sleeptime += a2dp->sbc.duration;
		if (len <= 0)
			return len;
		if(a2dp->len + a2dp->sbc.len > 678)	{ // time to prepare and send the packet
			dt.tv_sec=0;
			dt.tv_usec=1000000*a2dp->sbc.subbands*a2dp->sbc.blocks*a2dp->frame_count/io->rate;
			memset(&payload_header, 0, sizeof(payload_header));
			memset(&packet_header, 0, sizeof(packet_header));
			payload_header.frame_count=a2dp->frame_count;
			packet_header.v = 2;
			packet_header.pt = 1;
			packet_header.sequence_number = htons(a2dp->seq_num);
			packet_header.timestamp = htonl(a2dp->timestamp);
			packet_header.ssrc = htonl(1);
			a2dp->timestamp += (a2dp->sbc.blocks + 1)*4 * (a2dp->sbc.subbands + 1)*4;
			memcpy(a2dp->buf, &packet_header, sizeof(packet_header));
			memcpy(a2dp->buf + sizeof(packet_header), &payload_header, sizeof(payload_header));
			sleeptill(&a2dp->tsend, &dt);
			if((written = write(a2dp->sk,a2dp->buf,a2dp->len)) != a2dp->len) {
				DBG("Wrote %d not %d bytes; errno %s(%d)", written, a2dp->len,
					strerror(errno), errno);
			}
		        sbc_bps += written;
			a2dp->len = sizeof(packet_header)+sizeof(payload_header);
			a2dp->frame_count=0;
			sleeptime=0;
			a2dp->seq_num++;
		}
		a2dp->frame_count++;
		memcpy(a2dp->buf + a2dp->len, a2dp->sbc.data, a2dp->sbc.len);
		a2dp->len+=a2dp->sbc.len;
		if (a2dp->state == BT_CONNECTED)
			a2dp->num += len / a2dp->frame_bytes;
	}
	return datatoread / a2dp->frame_bytes;
}

static int a2dp_close(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	struct stream_cmd close_stream;
	struct close_stream_rsp close_resp;

	DBG("a2dp Destroying %p", a2dp);
	memset(&close_stream, 0, sizeof(close_stream));
	memset(&close_resp, 0, sizeof(close_resp));

	// the stream-close used to make the iTech headset lock up and require it to be powercycled
	// should be tested again now that we drain the queue properly

	init_request(&close_stream.header, AVDTP_CLOSE);
	close_stream.acp_seid = a2dp->seid;
	if (write(a2dp->control_sk, &close_stream, sizeof(close_stream)) != sizeof(close_stream))
	{
		fprintf(stderr, "Couldn't send close_stream (errno=%d:%s)\n", errno, strerror(errno));
		close(a2dp->control_sk);
		a2dp->control_sk = -1;
		close(a2dp->sk);
		a2dp->sk = -1;
	}

	a2dp->len = 0;

	a2dp_put(a2dp);
	DBG("OK");

	return 0;
}

static int a2dp_params(snd_pcm_ioplug_t *io, snd_pcm_hw_params_t *params)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	unsigned int period_bytes;

	DBG("a2dp %p", a2dp);

	a2dp->frame_bytes = (snd_pcm_format_physical_width(io->format) * io->channels) / 8;

	period_bytes = io->period_size * a2dp->frame_bytes;

	DBG("format %s rate %d channels %d", snd_pcm_format_name(io->format),
					io->rate, io->channels);

	DBG("frame_bytes %d period_bytes %d period_size %ld buffer_size %ld",
		a2dp->frame_bytes, period_bytes, io->period_size, io->buffer_size);

	return 0;
}

static int a2dp_prepare(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 13;

	a2dp->num = 0;

	a2dp->sbc.rate = io->rate;
	a2dp->sbc.channels = io->channels;

	return 0;
}

static int a2dp_drain(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	return 0;
}

static int a2dp_descriptors_count(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	if (a2dp->state == BT_CLOSED)
		return 0;

	return 1;
}

static int a2dp_descriptors(snd_pcm_ioplug_t *io, struct pollfd *pfds, unsigned int space)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	if (a2dp->state == BT_CLOSED)
		return 0;

	if (space < 1) {
		SNDERR("Can't fill in descriptors");
		return 0;
	}

	pfds[0].fd = a2dp->sk;
	pfds[0].events = POLLOUT;

	return 1;
}

static int a2dp_poll(snd_pcm_ioplug_t *io, struct pollfd *pfds,
			unsigned int nfds, unsigned short *revents)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	*revents = pfds[0].revents;

	if (a2dp->state == BT_CLOSED)
		return 0;

	if (pfds[0].revents & POLLHUP) {
		a2dp->state = BT_CLOSED;
		snd_pcm_ioplug_reinit_status(&a2dp->io);
	}

	return 0;
}

static snd_pcm_ioplug_callback_t a2dp_callback = {
	.start			= a2dp_start,
	.stop			= a2dp_stop,
	.pointer		= a2dp_pointer,
	.transfer		= a2dp_transfer2,
	.close			= a2dp_close,
	.hw_params		= a2dp_params,
	.prepare		= a2dp_prepare,
	.drain			= a2dp_drain,
	.poll_descriptors_count	= a2dp_descriptors_count,
	.poll_descriptors	= a2dp_descriptors,
	.poll_revents		= a2dp_poll,
};

static int a2dp_connect(snd_pcm_a2dp_t *a2dp)
{
	struct sockaddr_rc addr;
	socklen_t len;
	int sk;
	int control_sk = -1;
	DBG("a2dp %p (sk=%d, control_sk=%d)", a2dp, a2dp->sk, a2dp->control_sk);

	a2dp->seid = -1;

	if(a2dp->use_rfcomm)
	{
		sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
		if (sk < 0)
			return -errno;
		
		memset(&addr, 0, sizeof(addr));
		addr.rc_family = AF_BLUETOOTH;
		bacpy(&addr.rc_bdaddr, &a2dp->src);
		
		if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		{
			close(sk);
			return -errno;
		}
		
		memset(&addr, 0, sizeof(addr));
		addr.rc_family = AF_BLUETOOTH;
		bacpy(&addr.rc_bdaddr, &a2dp->dst);
		addr.rc_channel = 1;
		
		if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		{
			close(sk);
			return -errno;
		}

		memset(&addr, 0, sizeof(addr));
		len = sizeof(addr);
		
		if (getsockname(sk, (struct sockaddr *) &addr, &len) < 0)
		{
			close(sk);
			return -errno;
		}

		bacpy(&a2dp->src, &addr.rc_bdaddr);

		fcntl(sk, F_SETFL, fcntl(sk, F_GETFL) | O_NONBLOCK);
	}
	else
	{
		sk = connect_stream(&a2dp->src, &a2dp->dst, &control_sk, &a2dp->sbc, &a2dp->seid);
	}

	a2dp->sk = sk;
	a2dp->control_sk = control_sk;

	// Start listen thread
	a2dp->pause_writing = 0;
	a2dp->stop_writing = 0;
	pthread_create(&a2dp->hListenThread, NULL, listen_thread, (void*)a2dp);
	return 0;
}

static int a2dp_constraint(snd_pcm_a2dp_t *a2dp)
{
	snd_pcm_ioplug_t *io = &a2dp->io;
	snd_pcm_access_t access_list[] = {
		SND_PCM_ACCESS_RW_INTERLEAVED,
		SND_PCM_ACCESS_MMAP_INTERLEAVED,
	};
	unsigned int format[2], channel[2], rate[2];
	int err;

	DBG("TEST a2dp %p", a2dp);

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS, 2, access_list);
	if (err < 0)
		return err;

	format[0] = SND_PCM_FORMAT_S16_LE;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT, 1, format);
	if (err < 0)
		return err;

	channel[0] = 1;
	channel[1] = 2;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_CHANNELS, 2, channel);
	if (err < 0)
		return err;

	rate[0] = 44100;
	rate[1] = 48000;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_RATE, 2, rate);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 8192, 8192);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS, 2, 2);
	if (err < 0)
		return err;

	return 0;
}

#define MAX_CONNECTIONS 10

static snd_pcm_a2dp_t *connections[MAX_CONNECTIONS];

static snd_timer_t *timer = NULL;

static volatile sig_atomic_t __locked = 0;

static inline void a2dp_lock(void)
{
	while (__locked)
		usleep(100);

	__locked = 1;
}

static inline void a2dp_unlock(void)
{
	__locked = 0;
}

static inline snd_pcm_a2dp_t *a2dp_alloc(void)
{
	snd_pcm_a2dp_t *a2dp;
	DBG("init");
	a2dp = malloc(sizeof(*a2dp));
	if (!a2dp)
		return NULL;

	memset(a2dp, 0, sizeof(*a2dp));

	a2dp->refcnt = 1;
	a2dp->seq_num = 1;

	a2dp->state = BT_OPEN;

	sbc_init(&a2dp->sbc, 0L);

	return a2dp;
}

static inline void a2dp_free(snd_pcm_a2dp_t *a2dp)
{
	if (a2dp->sk > fileno(stderr))
		close(a2dp->sk);

	if (a2dp->control_sk > fileno(stderr))
		close(a2dp->control_sk);

	sbc_finish(&a2dp->sbc);

	free(a2dp);
}

static void a2dp_timer(snd_async_handler_t *async)
{
	snd_timer_t *handle = snd_async_handler_get_timer(async);
	snd_timer_read_t tr;
	int i, ticks = 0;

	while (snd_timer_read(handle, &tr, sizeof(tr)) == sizeof(tr))
		ticks += tr.ticks;

	a2dp_lock();

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		snd_pcm_a2dp_t *a2dp = connections[i];

		if (a2dp && a2dp->refcnt <= 0) {
			a2dp->timeout = ((a2dp->timeout * 1000) - ticks) / 1000;
			if (a2dp->timeout <= 0) {
				connections[i] = NULL;
				a2dp_free(a2dp);
			}
		}
	}

	a2dp_unlock();
}

void sighand(int signo)
{
  printf("Thread in signal handler %d\n", signo);
  return;
}

static void a2dp_init(void)
{
	snd_async_handler_t *async;
	snd_timer_info_t *info;
	snd_timer_params_t *params;
	long resolution;
	char timername[64];
	int err, i;

	// set up thread signal handler
	memset(&actions, 0, sizeof(actions));
	sigemptyset(&actions.sa_mask);
	actions.sa_flags = 0;
	actions.sa_handler = sighand;
	sigaction(SIGALRM,&actions,NULL);

	a2dp_lock();

	for (i = 0; i < MAX_CONNECTIONS; i++)
		connections[i] = NULL;

	a2dp_unlock();

	snd_timer_info_alloca(&info);
	snd_timer_params_alloca(&params);

	sprintf(timername, "hw:CLASS=%i,SCLASS=%i,CARD=%i,DEV=%i,SUBDEV=%i",
		SND_TIMER_CLASS_GLOBAL, SND_TIMER_CLASS_NONE, 0,
					SND_TIMER_GLOBAL_SYSTEM, 0);

	err = snd_timer_open(&timer, timername, SND_TIMER_OPEN_NONBLOCK);
	if (err < 0) {
		SNDERR("Can't open global timer");
		return;
	}

	err = snd_timer_info(timer, info);
	if (err < 0) {
		SNDERR("Can't get global timer info");
		return;
	}

	snd_timer_params_set_auto_start(params, 1);

	resolution = snd_timer_info_get_resolution(info);
	snd_timer_params_set_ticks(params, 1000000000 / resolution);
	if (snd_timer_params_get_ticks(params) < 1)
		snd_timer_params_set_ticks(params, 1);

	err = snd_timer_params(timer, params);
	if (err < 0) {
		SNDERR("Can't set global timer parameters");
		snd_timer_close(timer);
		return;
	}

	err = snd_async_add_timer_handler(&async, timer, a2dp_timer, NULL);
	if (err < 0) {
		SNDERR("Can't create global async callback");
		snd_timer_close(timer);
		return;
	}

	err = snd_timer_start(timer);

}

static void a2dp_exit(void)
{
	int err, i;

	err = snd_timer_stop(timer);

	err = snd_timer_close(timer);

	a2dp_lock();

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		snd_pcm_a2dp_t *a2dp = connections[i];

		if (a2dp) {
			connections[i] = NULL;
			a2dp_free(a2dp);
		}
	}

	a2dp_unlock();

}

SND_PCM_PLUGIN_DEFINE_FUNC(a2dp)
{
	snd_pcm_a2dp_t *a2dp = NULL;
	snd_config_iterator_t i, next;
	bdaddr_t src, dst;
	int err, n, pos = -1, use_rfcomm = 0;
	long bitpool = -1,subbnd = -1, blklen = -1;


	DBG("name %s mode %d", name, mode);

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id, *addr;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (!strcmp(id, "comment") || !strcmp(id, "type"))
			continue;

		if (!strcmp(id, "bdaddr") || !strcmp(id, "dst")) {
			if (snd_config_get_string(n, &addr) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			DBG("bdaddr/dest is %s", addr);
			str2ba(addr, &dst);
			continue;
		}

		if (!strcmp(id, "local") || !strcmp(id, "src")) {
			if (snd_config_get_string(n, &addr) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			str2ba(addr, &src);
			continue;
		}

		if (!strcmp(id, "sbc_bitpool")) {
			if ((err = snd_config_get_integer(n, &bitpool )) < 0 &&
					( bitpool < 0 || 254 < bitpool))  {
                                SNDERR("The field for bitpool must be an unsigned integer");
                                return err;
                        }
			continue;
		}

		if (!strcmp(id, "sbc_blklen")) {
			if ((err = snd_config_get_integer(n, &blklen)) < 0 &&
					( blklen != 4 && blklen != 8 && blklen != 12 && blklen != 16)) {
				SNDERR("The field for blocklen must be either 4, 8, 12 or 16");
				return err;
			}
			continue;
		}

		if (!strcmp(id, "sbc_subband")) {
			if ((err = snd_config_get_integer(n, &subbnd)) < 0 &&
				 ( subbnd != 4 && subbnd != 8)) {
				SNDERR("The field for subband must be either 4 or 8");
				return err;
			}
			continue;
		}


		if (!strcmp(id, "use_rfcomm")) {
			if ((err = snd_config_get_bool(n)) < 0) {
                                SNDERR("The field use_rfcomm must be a boolean type");
                                return err;
                        }
			use_rfcomm = err;
			continue;
		}

		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	a2dp_lock();

	for (n = 0; n < MAX_CONNECTIONS; n++) {
		if (connections[n]) {
			if (!bacmp(&connections[n]->dst, &dst) &&
					(!bacmp(&connections[n]->src, &src) ||
						!bacmp(&src, BDADDR_ANY))) {
				a2dp = connections[n];
				a2dp_get(a2dp);
				break;
			}
		} else if (pos < 0)
			pos = n;
	}

	if (!a2dp) {
		if (pos < 0) {
			SNDERR("Too many connections");
			return -ENOMEM;
		}

		a2dp = a2dp_alloc();
		if (!a2dp) {
			SNDERR("Can't allocate");
			return -ENOMEM;
		}

		connections[pos] = a2dp;

		a2dp->state  = BT_CONNECT;

		bacpy(&a2dp->src, &src);
		bacpy(&a2dp->dst, &dst);
		a2dp->use_rfcomm = use_rfcomm;
	}
	a2dp->sbc.subbands = 8; // safe default
	a2dp->sbc.blocks = 16; // safe default
	a2dp->sbc.bitpool = 32; // recommended value 53, safe default is 32

	if (bitpool != -1){
		DBG("sbc : bitpool %d" , (int)bitpool);
		a2dp->sbc.bitpool = (int)bitpool;
	}

	if (blklen != -1){
		DBG("sbc : subbands %d" , (int)subbnd);
		a2dp->sbc.subbands = (int)subbnd;
	}

	if (blklen != -1){
		DBG("sbc : blklen %d" , (int)blklen);
		a2dp->sbc.blocks = (int)blklen;
	}


	a2dp_unlock();

	if (a2dp->state != BT_CONNECTED) {
		err = a2dp_connect(a2dp);
		if (err < 0) {
			SNDERR("Can't connect");
			goto error;
		}

		a2dp->state = BT_CONNECTED;
	}

	a2dp->io.version      = SND_PCM_IOPLUG_VERSION;
	a2dp->io.name         = "Bluetooth Advanced Audio Distribution";
	a2dp->io.mmap_rw      = 0;
	a2dp->io.callback     = &a2dp_callback;
	a2dp->io.private_data = a2dp;

	err = snd_pcm_ioplug_create(&a2dp->io, name, stream, mode);
	if (err < 0)
		goto error;

	err = a2dp_constraint(a2dp);
	if (err < 0) {
		snd_pcm_ioplug_delete(&a2dp->io);
		goto error;
	}

	*pcmp = a2dp->io.pcm;
	return 0;

error:
	a2dp_put(a2dp);

	return err;
}

SND_PCM_PLUGIN_SYMBOL(a2dp);
