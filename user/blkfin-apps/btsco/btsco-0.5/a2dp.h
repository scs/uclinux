/*
 * a2dp.h
 * 
 * Brad Midgley
 * *************************************************************************
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

#ifndef A2DP_H
#define A2DP_H

#include <stdint.h>
 
/* AVDTP structures */

struct sbc_frame_header {
	uint8_t syncword:8;
	uint8_t subbands:1;
	uint8_t allocation_method:1;
	uint8_t channel_mode:2;
	uint8_t blocks:2;
	uint8_t sampling_frequency:2;
	uint8_t bitpool:8;
	uint8_t crc_check:8;
} __attribute__ ((packed));

/* packet components */

struct avdtp_header {
	uint8_t message_type:2;
	uint8_t packet_type:2;
	uint8_t transaction_label:4;
	uint8_t signal_id:6;
	uint8_t rfa0:2;
} __attribute__ ((packed));

struct acp_seid_info {
	uint8_t rfa0:1;
	uint8_t inuse0:1;
	uint8_t acp_seid:6;
	uint8_t rfa2:3;
	uint8_t tsep:1;
	uint8_t media_type:4;
} __attribute__ ((packed));

struct sbc_codec_specific_elements {
	// a2dp p. 20
	uint8_t channel_mode:4;
	uint8_t frequency:4;
	uint8_t allocation_method:2;
	uint8_t subbands:2;
	uint8_t block_length:4;
	uint8_t min_bitpool;
	uint8_t max_bitpool;
} __attribute__ ((packed));

struct mpeg12_codec_specific_elements {
	// a2dp p. 24
	uint8_t channel_mode:4;
	uint8_t crc:1;
	uint8_t layer3:1;
	uint8_t layer2:1;
	uint8_t layer1:1;
	uint8_t frequency:6;
	uint8_t mpf:1;
	uint8_t rfa:1;
	uint8_t bitrate0:7;
	uint8_t vbr:1;
	uint8_t bitrate1:8;
} __attribute__ ((packed));

// we are lucky these two components of the union are the same size!

union combined_codec_elements {
	struct sbc_codec_specific_elements sbc_elements;
	struct mpeg12_codec_specific_elements mpeg12_elements;
} __attribute__ ((packed));

// allow this value to be overridden
#ifndef MAX_ADDITIONAL_CODEC
#define MAX_ADDITIONAL_CODEC 4
#endif

#define MAX_ADDITIONAL_CODEC_OCTETS (MAX_ADDITIONAL_CODEC*sizeof(struct acp_seid_info))

/* packets */

struct sepd_req {
	struct avdtp_header header;
} __attribute__ ((packed));

struct sepd_resp {
	struct avdtp_header header;
	struct acp_seid_info infos[1 + MAX_ADDITIONAL_CODEC];
} __attribute__ ((packed));

struct getcap_req {
	struct avdtp_header header;
	uint8_t rfa1:2;
	uint8_t acp_seid:6;
} __attribute__ ((packed));

struct getcap_resp {
	struct avdtp_header header;

	uint8_t serv_cap;
	uint8_t serv_cap_len;

	uint8_t cap_type;
	uint8_t length;
	uint8_t media_type;
	uint8_t media_codec_type;

	union combined_codec_elements codec_elements;

} __attribute__ ((packed));

struct set_config {
	struct avdtp_header header;

	uint8_t rfa0:2;
	uint8_t acp_seid:6;
	uint8_t rfa1:2;
	uint8_t int_seid:6;

	uint8_t serv_cap;
	uint8_t serv_cap_len;

	uint8_t cap_type;
	uint8_t length;
	uint8_t media_type;
	uint8_t media_codec_type;

	union combined_codec_elements codec_elements;

} __attribute__ ((packed));

struct set_config_resp {
	struct avdtp_header header;

	// only present for an error

	uint8_t serv_cat;
	uint8_t error_code;
} __attribute__ ((packed));

struct open_stream_rsp {
	struct avdtp_header header;

	// only present for an error

	uint8_t error;
} __attribute__ ((packed));

struct stream_cmd {
	struct avdtp_header header;
	uint8_t rfa0:2;
	uint8_t acp_seid:6;
// todo: allow for additional acp_seid components, allowed for start, suspend, 
// but (strangely) not stream-close
} __attribute__ ((packed));

struct start_stream_rsp {
	struct avdtp_header header;

	// only present for an error

	uint8_t rfa0:2;
	uint8_t acp_seid:6;
	uint8_t error;
} __attribute__ ((packed));

struct close_stream_rsp {
	struct avdtp_header header;

	// only present for an error

	uint8_t error;
} __attribute__ ((packed));

// this is an rtp, not bluetooth header, so values are big endian
struct media_packet_header {
	uint8_t cc:4;
	uint8_t x:1;
	uint8_t p:1;
	uint8_t v:2;

	uint8_t pt:7;
	uint8_t m:1;

	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[0];
} __attribute__ ((packed));

struct media_payload_header {
	uint8_t frame_count:4;
	uint8_t rfa0:1;
	uint8_t is_last_fragment:1;
	uint8_t is_first_fragment:1;
	uint8_t is_fragmented:1;
} __attribute__ ((packed));

//Signal ids
#define AVDTP_DISCOVER 1
#define AVDTP_GET_CAPABILITIES 2
#define AVDTP_SET_CONFIGURATION 3
#define AVDTP_GET_CONFIGURATION 4
#define AVDTP_RECONFIGURE 5
#define AVDTP_OPEN 6
#define AVDTP_START 7
#define AVDTP_CLOSE 8
#define AVDTP_SUSPEND 9
#define AVDTP_ABORT 0xA
#define AVDTP_SECURITY_CONTROL 0xB

#define MEDIA_TRANSPORT_CATEGORY 1
#define MEDIA_CODEC 7

#define SBC_MEDIA_CODEC_TYPE 0
#define MPEG12_MEDIA_CODEC_TYPE 1
#define MPEG24_MEDIA_CODEC_TYPE 2
#define ATRAC_MEDIA_CODEC_TYPE 3

#define AUDIO_MEDIA_TYPE 0

//Packet types
#define PACKET_TYPE_SINGLE 0
#define PACKET_TYPE_START 1
#define PACKET_TYPE_CONTINUE 2
#define PACKET_TYPE_END 3

//Message Types
#define MESSAGE_TYPE_COMMAND 0
#define MESSAGE_TYPE_ACCEPT 2
#define MESSAGE_TYPE_REJECT 3

#define MEDIA_PACKET_HEADER_LENGTH 14

// .au manipulation
// Is there a header that defines this stuff so we don't have to?

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define COMPOSE_ID(a,b,c,d)     ((a) | ((b)<<8) | ((c)<<16) | ((d)<<24))
#define LE_SHORT(v)             (v)
#define LE_INT(v)               (v)
#define BE_SHORT(v)             bswap_16(v)
#define BE_INT(v)               bswap_32(v)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define COMPOSE_ID(a,b,c,d)     ((d) | ((c)<<8) | ((b)<<16) | ((a)<<24))
#define LE_SHORT(v)             bswap_16(v)
#define LE_INT(v)               bswap_32(v)
#define BE_SHORT(v)             (v)
#define BE_INT(v)               (v)
#else
#error "Wrong endian"
#endif
                                                                                                 
#define AU_MAGIC                COMPOSE_ID('.','s','n','d')
                                                                                                 
#define AU_FMT_ULAW             1
#define AU_FMT_LIN8             2
#define AU_FMT_LIN16            3

//Header format for the .snd files

struct au_header {
        uint32_t magic;         /* '.snd' */
        uint32_t hdr_size;      /* size of header (min 24) */
        uint32_t data_size;     /* size of data */
        uint32_t encoding;      /* see to AU_FMT_XXXX */
        uint32_t sample_rate;   /* sample rate */
        uint32_t channels;      /* number of channels (voices) */
};

#endif
