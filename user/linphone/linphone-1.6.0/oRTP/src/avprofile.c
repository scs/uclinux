/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2001  Simon MORLAT simon.morlat@linphone.org

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include <ortp/payloadtype.h>

char offset127=127; 
char offset0xD5=(char)0xD5; 
char offset0=0;

/* 
 * IMPORTANT : some compiler don't support the tagged-field syntax. Those
 * macros are there to trap the problem This means that if you want to keep
 * portability, payload types must be defined with their fields in the right
 * order.
 */
#if defined(_ISOC99_SOURCE)
// ISO C99's tagged syntax
#define TYPE(val)		.type=(val)
#define CLOCK_RATE(val)		.clock_rate=(val)
#define BITS_PER_SAMPLE(val)	.bits_per_sample=(val)
#define ZERO_PATTERN(val)	.zero_pattern=(val)
#define PATTERN_LENGTH(val)	.pattern_length=(val)
#define NORMAL_BITRATE(val)	.normal_bitrate=(val)
#define MIME_TYPE(val)		.mime_type=(val)
#define FMTP(val)		.FMTP=(val)
#elif defined(__GNUC__)
// GCC's legacy tagged syntax (even old versions have it)
#define TYPE(val)		type: (val)
#define CLOCK_RATE(val)		clock_rate: (val)
#define BITS_PER_SAMPLE(val)	bits_per_sample: (val)
#define ZERO_PATTERN(val)	zero_pattern: (val)
#define PATTERN_LENGTH(val)	pattern_length: (val)
#define NORMAL_BITRATE(val)	normal_bitrate: (val)
#define MIME_TYPE(val)		mime_type: (val)
#define FMTP(val)		FMTP: (val)
#else
// No tagged syntax supported
#define TYPE(val)		(val)
#define CLOCK_RATE(val)		(val)
#define BITS_PER_SAMPLE(val)	(val)
#define ZERO_PATTERN(val)	(val)
#define PATTERN_LENGTH(val)	(val)
#define NORMAL_BITRATE(val)	(val)
#define MIME_TYPE(val)		(val)
#define FMTP(val)		(val)

#endif

PayloadType payload_type_pcmu8000={
	TYPE( PAYLOAD_AUDIO_CONTINUOUS),
	CLOCK_RATE( 8000),
	BITS_PER_SAMPLE(8),
	ZERO_PATTERN( &offset127),
	PATTERN_LENGTH( 1),
	NORMAL_BITRATE( 64000),
	MIME_TYPE ("PCMU")
};

PayloadType payload_type_pcma8000={
	TYPE( PAYLOAD_AUDIO_CONTINUOUS),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE(8),
	ZERO_PATTERN( &offset0xD5),
	PATTERN_LENGTH( 1),
	NORMAL_BITRATE( 64000),
	MIME_TYPE ("PCMA")
};

PayloadType payload_type_pcm8000={
	TYPE( PAYLOAD_AUDIO_CONTINUOUS),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE(16),
	ZERO_PATTERN( &offset0),
	PATTERN_LENGTH(1),
	NORMAL_BITRATE( 128000),
	MIME_TYPE ("PCM")
};

PayloadType payload_type_lpc1016={
	TYPE( PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE( 0),
	ZERO_PATTERN( NULL),
	PATTERN_LENGTH( 0),
	NORMAL_BITRATE( 2400),
	MIME_TYPE ("1016")
};


PayloadType payload_type_gsm=
{
	TYPE( PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE( 0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH( 0),
	NORMAL_BITRATE( 13500),
	MIME_TYPE ("GSM")
};

PayloadType payload_type_g7231=
{
	TYPE( PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE( 0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH( 0),
	NORMAL_BITRATE( 6300),
	MIME_TYPE ("G723")
};

PayloadType payload_type_g729={
	TYPE( PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE( 0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH( 0),
	NORMAL_BITRATE( 8000),
	MIME_TYPE ("G729")
};

PayloadType payload_type_mpv=
{
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE( 256000),
	MIME_TYPE ("MPV")
};


PayloadType payload_type_h261={
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(0),
	MIME_TYPE ("H261")
};

PayloadType payload_type_h263={
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(256000),
	MIME_TYPE ("H263")
};

PayloadType payload_type_truespeech=
{
	TYPE( PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE( 0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH( 0),
	NORMAL_BITRATE(8536),
	MIME_TYPE ("TSP0")
};


#ifdef __cplusplus
extern "C"
{
#endif
RtpProfile av_profile;
#ifdef __cplusplus
}
#endif


void av_profile_init(RtpProfile *profile)
{
	rtp_profile_clear_all(profile);
	profile->name="AV profile";
	rtp_profile_set_payload(profile,0,&payload_type_pcmu8000);
	rtp_profile_set_payload(profile,1,&payload_type_lpc1016);
	rtp_profile_set_payload(profile,3,&payload_type_gsm);
	rtp_profile_set_payload(profile,4,&payload_type_g7231);
	rtp_profile_set_payload(profile,8,&payload_type_pcma8000);
	rtp_profile_set_payload(profile,18,&payload_type_g729);
	rtp_profile_set_payload(profile,31,&payload_type_h261);
	rtp_profile_set_payload(profile,32,&payload_type_mpv);
	rtp_profile_set_payload(profile,34,&payload_type_h263);
}
	
/* these are extra payload types that can be used dynamically */
PayloadType payload_type_lpc1015={
    TYPE( PAYLOAD_AUDIO_PACKETIZED),
    CLOCK_RATE(8000),
    BITS_PER_SAMPLE(0),
    ZERO_PATTERN(NULL),
    PATTERN_LENGTH(0),
    NORMAL_BITRATE(2400),
    MIME_TYPE ("1015")
};

PayloadType payload_type_speex_nb={
    TYPE( PAYLOAD_AUDIO_PACKETIZED),
    CLOCK_RATE(8000),
    BITS_PER_SAMPLE(0),
    ZERO_PATTERN(NULL),
    PATTERN_LENGTH(0),
    NORMAL_BITRATE(8000),   /*not true: 8000 is the minimum*/
    MIME_TYPE ("speex")
};

PayloadType payload_type_speex_wb={
    TYPE( PAYLOAD_AUDIO_PACKETIZED),
    CLOCK_RATE(16000),
    BITS_PER_SAMPLE(0),
    ZERO_PATTERN(NULL),
    PATTERN_LENGTH(0),
    NORMAL_BITRATE(28000),
    MIME_TYPE ("speex")
};

PayloadType payload_type_ilbc={
	 TYPE( PAYLOAD_AUDIO_PACKETIZED),
    CLOCK_RATE(8000),
    BITS_PER_SAMPLE(0),
    ZERO_PATTERN(NULL),
    PATTERN_LENGTH(0),
    NORMAL_BITRATE(13300), /* the minimum, with 30ms frames */ 
    MIME_TYPE ("iLBC"),
};

PayloadType payload_type_amr={
	TYPE(PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(0),
	MIME_TYPE ("AMR")
};

PayloadType payload_type_amrwb={
	TYPE(PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(16000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(0),
	MIME_TYPE ("AMR-WB")
};

PayloadType payload_type_mp4v={
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(0),
	MIME_TYPE ("MP4V-ES")
};


PayloadType payload_type_evrc0={
	TYPE(PAYLOAD_AUDIO_PACKETIZED),
	CLOCK_RATE(8000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(0),
	MIME_TYPE ("EVRC0")
};

 
PayloadType payload_type_h263_1998={
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(256000),
	MIME_TYPE ("H263-1998")
};

PayloadType payload_type_h263_2000={
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(0),
	MIME_TYPE ("H263-2000")
};

PayloadType payload_type_theora={
	TYPE( PAYLOAD_VIDEO),
	CLOCK_RATE(90000),
	BITS_PER_SAMPLE(0),
	ZERO_PATTERN(NULL),
	PATTERN_LENGTH(0),
	NORMAL_BITRATE(256000),
	MIME_TYPE ("theora")
};

