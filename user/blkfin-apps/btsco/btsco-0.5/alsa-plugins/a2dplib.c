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

// #define FASTTIMEOUTS 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include <pthread.h>


#include "a2dplib.h"
#include "a2dpd_protocol.h"
#include "a2dp_timer.h"
#include "a2dp_ipc.h"
#include "../sbc/sbc.h"
#include "../a2dp.h"

#define NBSDPRETRIESMAX 0
#define NONSPECAUDIO 1
#define BUFS 2048
// In fact sbc blocks are 76 bytes long, so a group of them is either 608 or 684 bytes
// So 650 or 678 makes no differences!
// However some devices may have longer transfer unit up to I saw omtu=733?

#define min(X, Y)  ((X) < (Y) ? (X) : (Y))
#define max(X, Y)  ((X) > (Y) ? (X) : (Y))
#define DBG(fmt, arg...) { if(errno!=0) printf("DEBUG: %s: (errno=%d:%s)" fmt "\n" , __FUNCTION__ , errno, strerror(errno), ## arg);\
        else printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg); errno=0;}


//#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
//#define DBG(D...)

/*
sdp_record_t*  g_recordP     = NULL;
sdp_session_t* g_sdpSessionP = NULL;
*/
//
// Handsfree Profile service constants
//
#define A2DP_SERVICE_NAME	"A2DP Audio Source"
#define A2DP_VERSION        0x0100

static struct sigaction actions;
/*
static sdp_record_t* a2dp_advertise_sdp(sdp_session_t* sdpSessionP)
{
        sdp_record_t *recordP=NULL;
        sdp_list_t *svclass=NULL, *rootlist=NULL, *protolist=NULL, *l2caplist=NULL, *avdtplist=NULL, *profileslist=NULL;
        uuid_t rootuuid, svcuuid, l2capuuid, avdtpuuid;
        sdp_profile_desc_t a2dpprofile;
        int error = 0;

        if(sdpSessionP)
        {
                // Generic service informations
                recordP = sdp_record_alloc();
                if (recordP)
                {
                        sdp_set_info_attr(recordP, A2DP_SERVICE_NAME, NULL, NULL);

                        // Add to Public Browse Group
                        sdp_uuid16_create(&rootuuid, PUBLIC_BROWSE_GROUP);
                        rootlist = sdp_list_append(NULL, &rootuuid);
                        sdp_set_browse_groups(recordP, rootlist);

                        // Set service class
                        sdp_uuid16_create(&svcuuid, AUDIO_SOURCE_SVCLASS_ID);
                        svclass = sdp_list_append(NULL, &svcuuid);
                        sdp_set_service_classes(recordP, svclass);

                        // Set protocols informations
                        // L2CAP
                        sdp_uuid16_create(&l2capuuid, L2CAP_UUID);
                        l2caplist = sdp_list_append(NULL, &l2capuuid);

                        // AVDTP
                        sdp_uuid16_create(&avdtpuuid, AVDTP_UUID);
                        avdtplist = sdp_list_append(NULL, &avdtpuuid);

                        // add protocols
                        protolist = sdp_list_append(NULL, l2caplist);
                        sdp_list_append(protolist, avdtplist);
                        protolist = sdp_list_append(NULL, protolist);
                        sdp_set_access_protos(recordP, protolist);

                        // Set profiles informations
                        // A2DP
                        sdp_uuid16_create(&a2dpprofile.uuid, AUDIO_SOURCE_PROFILE_ID);
                        a2dpprofile.version = A2DP_VERSION;
                        profileslist = sdp_list_append(NULL, &a2dpprofile);

                        // add profiles
                        sdp_set_profile_descs(recordP, profileslist);

                        // Register the record in the sdp session
                        error = sdp_record_register(sdpSessionP, recordP, 0);
                        if (error)
                        {
                                DBG("Unable to advertise service (0x%04hX)", error);
                                sdp_record_free(recordP);
                                recordP = NULL;
                        }
                }
                else
                {
                        DBG("Allocate for service description failed");
                }
        }
        else
        {
                DBG("No local sdp session available");
        }

        return recordP;
}

void a2dp_init(void) __attribute__ ((constructor));
void a2dp_exit(void) __attribute__ ((destructor));
*/
void memcpy_changeendian(void *dst, const void *src, int size)
{
	int i;
	const uint16_t *ptrsrc = src;
	uint16_t *ptrdst = dst;
	for (i = 0; i < size / 2; i++) {
		*ptrdst++ = htons(*ptrsrc++);
	}
}

// Prepare packet headers
void init_request(struct avdtp_header *header, int request_id)
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
int process_seid(int s, struct acp_seid_info *get_seid_resp, unsigned short *psm, sbc_t * sbc)
{
	int v, size;
	int seid = get_seid_resp->acp_seid;
	struct getcap_req put_req;
	struct getcap_resp cap_resp;
	struct set_config s_config;
	struct set_config_resp s_resp;
	struct stream_cmd open_stream;
	struct open_stream_rsp open_resp;

	memset(&put_req, 0, sizeof(put_req));
	init_request(&put_req.header, AVDTP_GET_CAPABILITIES);
	put_req.acp_seid = seid;

	if (write(s, &put_req, sizeof(put_req)) != sizeof(put_req)) {
		DBG("Couldn't request capabilities for SEID = %d", seid);
		return (-1);
	}

	if (read(s, &cap_resp, sizeof(cap_resp)) < sizeof(cap_resp) ||
	    cap_resp.header.message_type == MESSAGE_TYPE_REJECT || cap_resp.media_type != AUDIO_MEDIA_TYPE || cap_resp.media_codec_type != SBC_MEDIA_CODEC_TYPE) {
		DBG("Didn't receive SBC codec parameters (first) for SEID = %d", seid);
		return (-1);
	}

	DBG("Got capabilities response:\nservcap_cap=%d, servcap_len=%d,\ncap_type=%d, length=%d, media_type=%d, codec=%d",
	    cap_resp.serv_cap, cap_resp.serv_cap_len, cap_resp.cap_type, cap_resp.length, cap_resp.media_type, cap_resp.media_codec_type);

	memset(&s_config, 0, sizeof(s_config));
	init_request(&s_config.header, AVDTP_SET_CONFIGURATION);
	s_config.serv_cap = MEDIA_TRANSPORT_CATEGORY;
	s_config.acp_seid = seid;
	s_config.int_seid = 1;	//FIXME how should I choose the int_seid??
	s_config.cap_type = MEDIA_CODEC;
	s_config.length = 6;
	s_config.media_type = AUDIO_MEDIA_TYPE;
	s_config.media_codec_type = SBC_MEDIA_CODEC_TYPE;

	switch (sbc->channels) {
	case 1:
		v = 8;
		break;
	case 2:
	default:
		v = 2;
		break;
	}
	s_config.codec_elements.sbc_elements.channel_mode = v;

	switch (sbc->rate) {
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

	switch (sbc->subbands) {
	case 4:
		v = 2;
		break;
	case 8:
	default:
		v = 1;
		break;
	}
	s_config.codec_elements.sbc_elements.subbands = v;

	switch (sbc->blocks) {
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

	size = read(s, &s_resp, sizeof(s_resp));
	DBG("Got Set Configurations Response (%d bytes:msgtype=%d,pkttype=%d,lbl=%d,sig=%d,rfa=%d)",
	    size, s_resp.header.message_type, s_resp.header.packet_type, s_resp.header.transaction_label, s_resp.header.signal_id, s_resp.header.rfa0);

	memset(&open_stream, 0, sizeof(open_stream));
	init_request(&open_stream.header, AVDTP_OPEN);
	open_stream.acp_seid = seid;

	if (write(s, &open_stream, sizeof(open_stream)) != sizeof(open_stream)) {
		DBG("Couldn't open stream SEID = %d", seid);
		return (-1);
	}

	if (read(s, &open_resp, sizeof(open_resp)) < sizeof(open_resp) - 1 || open_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		DBG("Didn't receive open response confirm for SEID = %d", seid);
		return (-1);
	}

	*psm = 25;
	return 0;
}

int test_sdp(dst)
{
	int result = 0;

	return result;
}

// Connecting on PSM 25
int do_connect(bdaddr_t * src, bdaddr_t * dst, unsigned short psm, uint16_t * mtu)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk;
	unsigned int opt;
	int tries;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		DBG("Can't create socket.");
		return -1;
	}
#ifdef FASTTIMEOUTS
	// Set connection timeout
	struct timeval t = { 3, 0 };
	setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
	setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
#endif
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);
	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DBG("Can't bind socket.");
		return -1;
	}

	/* Get default options */
	opt = sizeof(opts);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		DBG("Can't get default L2CAP options.");
		return -1;
	}

	/* Set new options */
	if (mtu && *mtu) {
		opts.omtu = *mtu;
		//opts.imtu = *mtu;
	}
	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, opt) < 0) {
		DBG("Can't set L2CAP options.");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(psm);

	tries = 0;
	while (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		char* tmpaddr = batostr(&addr.l2_bdaddr);
		DBG("Can't connect to %s on psm %d.", tmpaddr, psm);
		free(tmpaddr);
		if (++tries > NBSDPRETRIESMAX) {
			close(sk);
			return -1;
		}
		sleep(1);
	}
	opt = sizeof(opts);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) < 0) {
		DBG("Can't get L2CAP options.");
		close(sk);
		return -1;
	}
	//DBG( "Connected psm=%d sk=%d [imtu %d, omtu %d, flush_to %d]", psm, sk, opts.imtu, opts.omtu, opts.flush_to);

	if (mtu)
		*mtu = opts.omtu;

	return sk;
}

// Detect whether A2DP Sink is present at the destination or not
int detect_a2dp(bdaddr_t * src, bdaddr_t * dst, unsigned short *psm, unsigned long *flags)
{
	sdp_session_t *sess;
	sdp_list_t *attrid, *search, *seq, *next;
	sdp_data_t *pdlist;
	uuid_t group;
	uint32_t range = 0x0000ffff;
	int err;
	int tries;

#ifdef FASTTIMEOUTS
	// Try to connect an L2CAP socket to the sdp psm with short timeout for user interaction
	int tmpsk = do_connect(src, dst, 1, NULL);
	if (tmpsk > 0) {
		close(tmpsk);
	} else {
		DBG("Warning: failed to connect to SDP server");
		return -1;
	}
#endif
	tries = 0;
	while (!(sess = sdp_connect(src, dst, SDP_RETRY_IF_BUSY))) {
		DBG("retrying sdp connect.");
		if (++tries > NBSDPRETRIESMAX) {
			break;
		}
		sleep(1);
	}
	if (!sess) {
		DBG("Warning: failed to connect to SDP server");
		if (psm)
			*psm = 25;
		if (flags)
			*flags = 0;
		return 0;
	}

	/* 0x1108->all? 0x1101->rf sink 0x111e->handsfree 0x1108->headset */
	sdp_uuid16_create(&group, 0x110d);
	search = sdp_list_append(0, &group);
	attrid = sdp_list_append(0, &range);
	err = sdp_service_search_attr_req(sess, search, SDP_ATTR_REQ_RANGE, attrid, &seq);
	sdp_list_free(search, 0);
	sdp_list_free(attrid, 0);

	if (err) {
		DBG("Service Search failed.");
		sdp_close(sess);
		return -1;
	}

	for (; seq; seq = next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;

		DBG("Found A2DP Sink");
		if (psm)
			*psm = 25;

		next = seq->next;
		free(seq);
		sdp_record_free(rec);
	}

	sdp_uuid16_create(&group, PNP_INFO_SVCLASS_ID);
	search = sdp_list_append(0, &group);
	attrid = sdp_list_append(0, &range);
	err = sdp_service_search_attr_req(sess, search, SDP_ATTR_REQ_RANGE, attrid, &seq);
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

		DBG("Product ID %04x:%04x:%04x", vendor, product, version);

		if (vendor == 0x1310 && product == 0x0100 && version == 0x0104) {
			DBG("Enabling GCT media payload workaround");
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

int connect_stream(bdaddr_t * src, bdaddr_t * dst, int *cmdfd_return, sbc_t * sbc, int *seid_return, int *omtu)
{
	int cmdfd = -1;
	struct sepd_req discover_req;
	struct sepd_resp discover_resp;
	struct stream_cmd start_stream;
	struct start_stream_rsp start_resp;
	int seid, nb_seid;
	int size;
	int i;
	unsigned short psm_cmd, psm_stream = 25;
	unsigned long flags = 0;
	int streamfd = -1;
	uint16_t mtu = 0;
	int tries, res;

	if (detect_a2dp(src, dst, &psm_cmd, &flags) < 0) {
		char* tmpaddr=batostr(dst);
		DBG("could not find A2DP services on device %s", tmpaddr);
		free(tmpaddr);
		return -1;
	} else {
		DBG("Found A2DP Sink at the destination (psm_cmd=%d)", psm_cmd);
	}

	psm_cmd = 25;
	cmdfd = do_connect(src, dst, psm_cmd, &mtu);
	if (cmdfd < 0) {
		DBG("cannot open psm_cmd = %d", psm_cmd);
		return -1;
	}
	// avdt_discover_req
	memset(&discover_req, 0, sizeof(discover_req));
	init_request(&discover_req.header, AVDTP_DISCOVER);

	res = write(cmdfd, &discover_req, sizeof(discover_req));
	if (res != sizeof(discover_req)) {
		DBG("couldn't send avdtp_discover (res=%d)", res);
		close(cmdfd);
		return -1;
	} else {
		DBG("Sent the Stream End Point Discovery Command");
	}
	tries = 0;
	memset(&discover_resp, 0, sizeof(discover_resp));

	// SONORIX sends us a discover signal we should answer but we will discard
	while (tries < 10) {
		size = a2dp_handle_avdtp_message(NULL, cmdfd, &discover_req.header, &discover_resp.header, sizeof(discover_resp));
		if (size > 0) {
			// Answer to what we send
			break;
		} else {
			// Not answer
			usleep(100);
			tries++;
		}
	}

	if (size > sizeof(discover_resp.header)) {
		DBG("Got a Stream End Point Discovery (%d bytes) Response (msgtype=%d,pkttype=%d,lbl=%d,sig=%d,rfa=%d)",
		    size, discover_resp.header.message_type, discover_resp.header.packet_type, discover_resp.header.transaction_label, discover_resp.header.signal_id, discover_resp.header.rfa0);
		for (i = 0; i < size; i++)
			printf("%02X", (int) (*(((char *) &discover_resp) + i)));
		printf("\n");
	} else {
		DBG("couldn't get avdtp_discover (size=%d, min=%d, max=%d)", size, sizeof(discover_resp.header), sizeof(discover_resp));
		close(cmdfd);
		return -1;
	}

	seid = -1;
	if(size<sizeof(discover_resp.header)) {
		DBG("Received invalid capabilities (size=%d, wanted=%d)", size, sizeof(discover_resp.header));
		return -1;
	}

	nb_seid = (size - sizeof(discover_resp.header)) / sizeof(struct acp_seid_info);

	DBG("received %d capabilities", nb_seid);

	for (i = 0; i < nb_seid; i++) {
		if (process_seid(cmdfd, &discover_resp.infos[i], &psm_stream, sbc) == 0) {
			seid = discover_resp.infos[i].acp_seid;
			break;
		}
	}

	if (seid == -1) {
		//We have not found the seid that we want
		DBG("couldn't locate the correct seid");
		return -1;
	}

	// open the stream
	streamfd = do_connect(src, dst, psm_stream, &mtu);
	if (streamfd < 0) {
		DBG("cannot open psm_stream = %d", psm_stream);
		return -1;
	}
	// start the stream

	memset(&start_stream, 0, sizeof(start_stream));
	init_request(&start_stream.header, AVDTP_START);
	start_stream.acp_seid = seid;

	if (write(cmdfd, &start_stream, sizeof(start_stream)) != sizeof(start_stream)) {
		DBG("couldn't send start_stream");
		close(streamfd);
		close(cmdfd);
		return -1;
	}

	DBG("Sent stream start(seid=%d)", seid);

	if (read(cmdfd, &start_resp, sizeof(start_resp)) < sizeof(start_resp) - 2 || start_resp.header.message_type == MESSAGE_TYPE_REJECT) {
		DBG("didn't receive start_resp confirm for seid = %d", seid);
		close(streamfd);
		close(cmdfd);
		return (-1);
	}

	DBG("Got start stream confirm");

	*omtu = A2DPMAXIMUMTRANSFERUNITSIZE;	//mtu;
	*seid_return = seid;
	*cmdfd_return = cmdfd;
	return streamfd;
}

typedef struct snd_pcm_a2dp {
	A2DPSETTINGS settings;
	bdaddr_t src;
	bdaddr_t dst;
	int sk;
	int control_sk;
	sbc_t sbc;
	unsigned char buf[1024];	// contain sbc encoded data, incrementally filled
	unsigned int len;	// number of valid bytes in buf
	unsigned int frame_bytes;	// fixed when initializing

	char bufe[BUFS];	// temporary encoding buffer
	int lenbufe;		//=0;

	time_t timestamp;	//=0;
	uint16_t seq_num;	//=1;
	int frame_count;	//=0; // Number of sbc frames in one AVDTP packet

	int mtu;		//=A2DPMAXIMUMTRANSFERUNITSIZE
	int seid;

	// Bluetooth bandwith used
	int bandwithcount;
	struct timeval bandwithtimestamp;

	// Used to control stream from headset
	int stop_writing;	// = 0;
	int pause_writing;	// = 0;
	pthread_t hListenThread;

} snd_pcm_a2dp_t;

// We have pcm data to send through bluetooth
int a2dp_transfer_raw(LPA2DP a2dp, const char *pcm_buffer, int pcm_buffer_size)
{
	// No error
	int result = 0;
	struct media_packet_header packet_header;
	struct media_payload_header payload_header;
	int codesize, datatoread;
	int written;

	// Check parameter
	if (a2dp == 0 || pcm_buffer == 0 || pcm_buffer_size == 0)
		return EINVAL;

	// How much data can be encoded by sbc at a time?
	// 16 bits * 2 channels * 16 blocks * 8 subbands = 4096bits = 512 o
	codesize = a2dp->sbc.subbands * a2dp->sbc.blocks * a2dp->sbc.channels * 2;
	// 44 bitpool?
	//codesize=a2dp->sbc.bitpool*a2dp->sbc.subbands*a2dp->sbc.blocks/8;
	datatoread = min((BUFS - a2dp->lenbufe), pcm_buffer_size);

	// Enqueue data in bufe
	if (a2dp->lenbufe + datatoread < BUFS) {
		// Append data to bufe, for sbc encoding
		memcpy_changeendian(a2dp->bufe + a2dp->lenbufe, pcm_buffer, datatoread);
		a2dp->lenbufe += datatoread;
	} else {
		datatoread = 0;
	}

	result = datatoread;

	// If bufe is full, encode
	if (a2dp->lenbufe >= codesize) {
		// Enough data to encode (sbc wants 1k blocks)
		int encoded;
		encoded = sbc_encode(&(a2dp->sbc), a2dp->bufe, codesize);	//encode

		if (encoded <= 0)
			return encoded;

		memmove(a2dp->bufe, a2dp->bufe + encoded, a2dp->lenbufe - encoded);	// Shift the bufe
		a2dp->lenbufe -= encoded;

		// Send data through bluetooth
		if (a2dp->len + a2dp->sbc.len >= a2dp->mtu) {
			// time to prepare and send the packet
			memset(&payload_header, 0, sizeof(payload_header));
			memset(&packet_header, 0, sizeof(packet_header));
			payload_header.frame_count = a2dp->frame_count;
			packet_header.v = 2;
			packet_header.pt = 1;
			packet_header.cc = 0;
			packet_header.sequence_number = htons(a2dp->seq_num);
			packet_header.timestamp = htonl(a2dp->timestamp);
			packet_header.ssrc = htonl(1);

			a2dp->timestamp += (a2dp->sbc.blocks + 1) * 4 * (a2dp->sbc.subbands + 1) * 4;
			memcpy(a2dp->buf, &packet_header, sizeof(packet_header));
			memcpy(a2dp->buf + sizeof(packet_header), &payload_header, sizeof(payload_header));
			if (a2dp->sk > 0) {
			/*
				// Check if data are to be read
				// Not seen a device showing this yet
				fd_set readfds;
				struct timeval zero_timeout = { 0, 0 };
				FD_ZERO(&readfds);
				FD_SET(a2dp->sk, &readfds);
				int iselect = select(1, &readfds, NULL, NULL, &zero_timeout);
				if (iselect > 0) {
					if (FD_ISSET(a2dp->sk, &readfds)) {
						a2dp_handle_avdtp_message(a2dp, a2dp->sk, NULL, NULL, 0);
					}
				}
			*/
				// Pause?
				// The value 0 have finally been tested ;)
				// However, we may safely simulate a failed write
				if (!a2dp->pause_writing) {
					// Send our data
					if ((written = write(a2dp->sk, a2dp->buf, a2dp->len)) != a2dp->len) {
						// Error while sending data
						DBG("Wrote %d not %d bytes.", written, a2dp->len);
						/*
						if (errno == EAGAIN) {
							usleep(1);
							if ((written = write(a2dp->sk, a2dp->buf, a2dp->len)) != a2dp->len) {
								// Error while sending data
								DBG("Wrote %d not %d bytes. (2)", written, a2dp->len);
								// Return the error
								result = written;
							}
						}
						else
						{
						}
						*/
						// Return the error
						result = written;
					} else {
						// Measure bandwith usage
						struct timeval now = { 0, 0 };
						struct timeval interval = { 0, 0 };

						if(a2dp->bandwithtimestamp.tv_sec==0)
							gettimeofday(&a2dp->bandwithtimestamp, NULL);

						// See if we must wait again
						gettimeofday(&now, NULL);
						timersub(&now, &a2dp->bandwithtimestamp, &interval);
						if(interval.tv_sec>0) {
							DBG("Bandwith: %d (%d kbps) %d", a2dp->bandwithcount, a2dp->bandwithcount/128, a2dp->sbc.bitpool);
							a2dp->bandwithtimestamp = now;
							a2dp->bandwithcount = 0;
						}

						a2dp->bandwithcount += written;
					}
					
					
				} else {
					// Make the upper layer believe we sent data
					//result = a2dp->len;
				}
			}
			// Reset buffer of data to send
			a2dp->len = sizeof(struct media_packet_header) + sizeof(struct media_payload_header);
			a2dp->frame_count = 0;
			a2dp->seq_num++;
		}
		// Append sbc encoded data to buf, until buf reaches A2DPMAXIMUMTRANSFERUNITSIZE to send
		a2dp->frame_count++;
		memcpy(a2dp->buf + a2dp->len, a2dp->sbc.data, a2dp->sbc.len);
		a2dp->len += a2dp->sbc.len;
	}

	return result;
}
/*
static void init_response(struct avdtp_header *header, int response_type)
{
	// leave signal_id and transaction label since we are reusing the request
	header->packet_type = PACKET_TYPE_SINGLE;
	header->message_type = response_type;

	// clear rfa bits
	header->rfa0 = 0;
}
*/
// monitor the control connection for pause/play signals from headset
// note this signaling is in the avdtp core; avrcp signaling is different
static void *listen_thread(void *param)
{
	snd_pcm_a2dp_t *a2dp = (snd_pcm_a2dp_t *) param;

	if (a2dp->control_sk < 0) {
		DBG("Listen thread not started [control_sk=%d]", a2dp->control_sk);
		return NULL;
	}

	DBG("Listen thread running [control_sk=%d]", a2dp->control_sk);

//#ifdef FASTTIMEOUTS
	// Set a timeout to close thread
	struct timeval t = { 1, 0 };
	setsockopt(a2dp->control_sk, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
	setsockopt(a2dp->control_sk, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
//#endif

	// Loop until end of writing
	while (!a2dp->stop_writing) {
		if (a2dp_handle_avdtp_message(a2dp, a2dp->control_sk, NULL, NULL, 0) < 0) {
			// Error
			//FIXME we must reconnect
			usleep(100 * 1000);
		}
		// Make sure we do not spin in case of errors
		usleep(10 * 1000);
	}

	return NULL;
}

int a2dp_connect(snd_pcm_a2dp_t * a2dp)
{
	//struct sockaddr_rc addr;
	//socklen_t len;
	int sk = -1;
	int control_sk = -1;
	errno = 0;
	/*
	   if(a2dp->use_rfcomm) {
	   sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	   if (sk < 0)
	   return -errno;

	   memset(&addr, 0, sizeof(addr));
	   addr.rc_family = AF_BLUETOOTH;
	   bacpy(&addr.rc_bdaddr, &a2dp->src);

	   if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	   close(sk);
	   return -errno;
	   }

	   memset(&addr, 0, sizeof(addr));
	   addr.rc_family = AF_BLUETOOTH;
	   bacpy(&addr.rc_bdaddr, &a2dp->dst);
	   addr.rc_channel = 1;

	   if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	   close(sk);
	   return -errno;
	   }

	   memset(&addr, 0, sizeof(addr));
	   len = sizeof(addr);

	   if (getsockname(sk, (struct sockaddr *) &addr, &len) < 0) {
	   close(sk);
	   return -errno;
	   }

	   bacpy(&a2dp->src, &addr.rc_bdaddr);

	   //fcntl(sk, F_SETFL, fcntl(sk, F_GETFL) | O_NONBLOCK);
	   } else { */
	sk = connect_stream(&a2dp->src, &a2dp->dst, &control_sk, &a2dp->sbc, &a2dp->seid, &a2dp->mtu);
	//}

	a2dp->sk = sk;
	a2dp->control_sk = control_sk;

	// Start listen thread
	a2dp->pause_writing = 0;
	a2dp->stop_writing = 0;

	if (sk > 0) {
		// Set pthread stack size to decrease unused memory usage
		pthread_attr_t tattr;
		size_t size = PTHREAD_STACK_MIN;
		int ret = pthread_attr_init(&tattr);
		ret = pthread_attr_setstacksize(&tattr, size);
		pthread_create(&a2dp->hListenThread, &tattr, listen_thread, (void *) a2dp);
		pthread_attr_destroy(&tattr);
	}

	return sk;
}

snd_pcm_a2dp_t *a2dp_alloc(void)
{
	snd_pcm_a2dp_t *a2dp;
	a2dp = malloc(sizeof(*a2dp));
	if (!a2dp)
		return NULL;

	memset(a2dp, 0, sizeof(*a2dp));
	a2dp->seq_num = 1;
	a2dp->mtu = A2DPMAXIMUMTRANSFERUNITSIZE;
	a2dp->len = sizeof(struct media_packet_header) + sizeof(struct media_payload_header);

	sbc_init(&a2dp->sbc, 0L);
	a2dp->sbc.rate = A2DPD_FRAME_RATE;
	a2dp->sbc.subbands = 8;	// safe default
	a2dp->sbc.blocks = 16;	// safe default
	a2dp->sbc.bitpool = 32;	// recommended value 53, safe default is 32
	return a2dp;
}

void a2dp_free(snd_pcm_a2dp_t * a2dp)
{
	DBG("");
	if (a2dp->sk > 0)
		close(a2dp->sk);
	if (a2dp->control_sk > 0)
		close(a2dp->control_sk);

	sbc_finish(&a2dp->sbc);

	free(a2dp);
}

static void sighand(int signo)
{
	return;
}

void a2dp_init(void)
{
	// set up thread signal handler
	memset(&actions, 0, sizeof(actions));
	sigemptyset(&actions.sa_mask);
	actions.sa_flags = 0;
	actions.sa_handler = sighand;
	sigaction(SIGALRM, &actions, NULL);

	// Start sdp advertising
	/*
	   g_sdpSessionP = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
	   g_recordP = a2dp_advertise_sdp(g_sdpSessionP);
	 */
}

void a2dp_exit(void)
{
}

LPA2DP a2dp_new(A2DPSETTINGS* settings)
{
	snd_pcm_a2dp_t *a2dp = NULL;

	if(settings) {
		a2dp = a2dp_alloc();

		DBG("%s, %d", settings->bdaddr, settings->framerate);

		if (a2dp) {
			memcpy(&a2dp->settings, settings, sizeof(a2dp->settings));
			a2dp->sbc.rate = settings->framerate;
			a2dp->sbc.channels = max(1, min(settings->channels, 2));
			a2dp->sbc.bitpool = settings->sbcbitpool;
			if(settings->channels==1)
				a2dp->sbc.joint=1;
			bacpy(&a2dp->src, BDADDR_ANY);
			str2ba(settings->bdaddr, &a2dp->dst);

			if (a2dp_connect(a2dp) < 0) {
				DBG("Can't connect");
				a2dp_free(a2dp);
				a2dp=NULL;
			}
		}
	}
	return a2dp;
}

void a2dp_destroy(LPA2DP a2dp)
{
	struct stream_cmd close_stream;
	struct close_stream_rsp close_resp;

	DBG("Begin");
	a2dp->stop_writing = 1;
	pthread_kill(a2dp->hListenThread, SIGALRM);
	pthread_join(a2dp->hListenThread, NULL);

	memset(&close_stream, 0, sizeof(close_stream));
	memset(&close_resp, 0, sizeof(close_resp));

	// the stream-close used to make the iTech headset lock up and require it to be powercycled
	// should be tested again now that we drain the queue properly
	//FIXME Should be tested again now that we read the answer, Sonorix used to do something similar and no longer does it!

	init_request(&close_stream.header, AVDTP_CLOSE);
	close_stream.acp_seid = a2dp->seid;
	if (a2dp->control_sk > 0) {
		if(write(a2dp->control_sk, &close_stream, sizeof(close_stream)) == sizeof(close_stream)) {
			// Receive close stream answer if any?
			int i, size;
			DBG("Receiving answer to close stream");
			size = recv(a2dp->control_sk, &close_stream, sizeof(close_stream), 0);
			DBG("Received answer size=%d", size);
			for (i = 0; i < size; i++)
				printf("%02X", (int) (*(((char *) &close_stream) + i)));
			printf("\n");
		} else {
			DBG("Couldn't send close_stream");
		}
	}

	a2dp_free(a2dp);
	DBG("a2dp_destroy(%p) OK", a2dp);
}

int a2dp_make_listen_socket(unsigned short psm)
{
	char *lpszError = NULL;
	int sockfd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

	if (sockfd >= 0) {
		struct sockaddr_l2 addr;
		memset(&addr, 0, sizeof(addr));
		addr.l2_family = AF_BLUETOOTH;
		bacpy(&addr.l2_bdaddr, BDADDR_ANY);
		addr.l2_psm = htobs(psm);
		if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) >= 0) {
			/*
			   struct l2cap_options opts;
			   unsigned int iOptSize = sizeof(opts);
			   // Get default options
			   if (getsockopt(sockfd, SOL_L2CAP, L2CAP_OPTIONS, &opts, &opt) >= 0)
			   {
			   if (setsockopt(sockfd, SOL_L2CAP, L2CAP_OPTIONS, &opts, opt) >= 0)
			   {
			 */
			if (listen(sockfd, 5) >= 0) {
			} else {
				lpszError = "Can't listen.";
			}
			/*
			   }
			   else
			   {
			   lpszError = "Can't get default L2CAP options.";
			   }
			   }
			   else
			   {
			   lpszError = "Can't set L2CAP options.";
			   }
			 */
		} else {
			lpszError = "Can't bind socket (already used?).";
		}
	} else {
		lpszError = "Can't create socket.";
	}

	if (lpszError) {
		DBG("%s", lpszError);
		close(sockfd);
		sockfd = -1;
	}

	return sockfd;
}

int a2dp_wait_connection(int sockfd, char *szRemote, int iRemoteSize, uint16_t * mtu)
{
	// Wait client connection
	struct sockaddr_l2 addr;
	socklen_t addrlen = sizeof(addr);

	// Timeouts each second to read variables
	struct timeval t = { 1, 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));

	int new_fd = accept(sockfd, (struct sockaddr *) &addr, &addrlen);

	if (szRemote)
		*szRemote = '\0';

	if (new_fd >= 0) {
		// Get default options
		struct l2cap_options opts;
		unsigned int iOptSize = sizeof(opts);
		if (getsockopt(sockfd, SOL_L2CAP, L2CAP_OPTIONS, &opts, &iOptSize) >= 0) {
			if (mtu && opts.imtu)
				*mtu = opts.imtu;
			if (mtu && opts.omtu)
				*mtu = opts.omtu;
			if (!(*mtu))
				*mtu = A2DPMAXIMUMTRANSFERUNITSIZE;
		}
		//DBG("Connected [imtu %d, omtu %d, flush_to %d]", opts.imtu, opts.omtu, opts.flush_to);

		if (szRemote) {
			char* tmpaddr = batostr(&addr.l2_bdaddr);
			strncpy(szRemote, tmpaddr, iRemoteSize);
			free(tmpaddr);
			szRemote[iRemoteSize - 1] = '\0';
		}
	} else {
		sleep(1);
	}
	return new_fd;
}

// This function handle the bluetooth connection
int a2dp_handle_avdtp_message(LPA2DP a2dp, int sockfd, struct avdtp_header *sent_packet, struct avdtp_header *answer, int answer_size)
{
	int result = 0;
	int wrresult = 0;

	char lpFrame[A2DPMAXIMUMTRANSFERUNITSIZE];
	int iReceived = recv(sockfd, lpFrame, sizeof(lpFrame), 0);
	struct avdtp_header *pkt_hdr = (struct avdtp_header *) lpFrame;
	if (iReceived > 0) {
		// Manage the packet
		if (sent_packet == NULL) {
			int i;
			printf("socket %d: Received %d bytes\n", sockfd, iReceived);
			for (i = 0; i < iReceived; i++) {
				char c = lpFrame[i];
				if (i % 16 == 0)
					printf("%05d: ", i);
				printf("%02x ", c);
				if (i % 16 == 15)
					printf("\n");
			}
			printf("\n");
			result = 0;
		} else if ((pkt_hdr->message_type == MESSAGE_TYPE_ACCEPT) && (pkt_hdr->signal_id == sent_packet->signal_id)) {
			// Got expected answer
			memcpy(answer, lpFrame, answer_size > iReceived ? answer_size : iReceived);
			result = iReceived;
		} else {
			// Got bad answer
			result = 0;
		}

		// Reply to the packet by rejecting it
		if (pkt_hdr->message_type == MESSAGE_TYPE_COMMAND) {
			int accepted = 0;
			if (pkt_hdr->signal_id == AVDTP_DISCOVER) {
				DBG("Received signal AVDTP_DISCOVER(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_GET_CAPABILITIES) {
				DBG("Received signal AVDTP_GET_CAPABILITIES(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_SET_CONFIGURATION) {
				DBG("Received signal AVDTP_SET_CONFIGURATION(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_GET_CONFIGURATION) {
				DBG("Received signal AVDTP_GET_CONFIGURATION(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_RECONFIGURE) {
				DBG("Received signal AVDTP_RECONFIGURE(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_OPEN) {
				DBG("Received signal AVDTP_OPEN(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_START) {
				DBG("Received signal AVDTP_START(%d) from set", pkt_hdr->signal_id);
				if(a2dp)
					a2dp->pause_writing = 0;
				accepted = 1;
			} else if (pkt_hdr->signal_id == AVDTP_CLOSE) {
				DBG("Received signal AVDTP_CLOSE(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_SUSPEND) {
				DBG("Received signal AVDTP_SUSPEND(%d) from set", pkt_hdr->signal_id);
				if(a2dp)
					a2dp->pause_writing = 1;
				accepted = 1;
			} else if (pkt_hdr->signal_id == AVDTP_ABORT) {
				DBG("Received signal AVDTP_ABORT(%d) from set", pkt_hdr->signal_id);
			} else if (pkt_hdr->signal_id == AVDTP_SECURITY_CONTROL) {
				DBG("Received signal AVDTP_SECURITY_CONTROL(%d) from set", pkt_hdr->signal_id);
			}  else {
				DBG("Unexpected headset directive %d", pkt_hdr->signal_id);
			}

			DBG("Answering command packet (msgtype=%s,signal=%d)", accepted ? "MESSAGE_TYPE_ACCEPT" : "MESSAGE_TYPE_REJECT", pkt_hdr->signal_id);
			// Reject a command received
			pkt_hdr->message_type = accepted ? MESSAGE_TYPE_ACCEPT : MESSAGE_TYPE_REJECT;

			wrresult = write(sockfd, pkt_hdr, sizeof(*pkt_hdr));

			if (wrresult != sizeof(*pkt_hdr)) {
				DBG("FAILED Answering command packet (msgtype=%s,signal=%d) wrresult=%d/%d", accepted ? "MESSAGE_TYPE_ACCEPT" : "MESSAGE_TYPE_REJECT", pkt_hdr->signal_id,
				    wrresult, sizeof(*pkt_hdr));
			}
		} else {
			DBG("Read non command packet (msgtype=%d,signal=%d)", pkt_hdr->message_type, pkt_hdr->signal_id);
		}
	} else {
		result = iReceived;
		if (errno != EAGAIN)
			printf("socket %d: Receive failed %d\n", sockfd, iReceived);
	}

	return result;
}
