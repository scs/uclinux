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

#ifndef PAYLOADTYPE_H
#define PAYLOADTYPE_H
#include <ortp/port.h>

/* flags for PayloadType::flags */

#define	PAYLOAD_TYPE_ALLOCATED (1)
	/* private flags for future use by ortp */
#define	PAYLOAD_TYPE_PRIV1 (1<<1)
#define	PAYLOAD_TYPE_PRIV2 (1<<2)
#define	PAYLOAD_TYPE_PRIV3 (1<<3)
	/* user flags, can be used by the application on top of oRTP */
#define	PAYLOAD_TYPE_USER_FLAG_0 (1<<4)
#define	PAYLOAD_TYPE_USER_FLAG_1 (1<<5)
#define	PAYLOAD_TYPE_USER_FLAG_2 (1<<6)
	/* ask for more if you need*/

#define PAYLOAD_AUDIO_CONTINUOUS 0
#define PAYLOAD_AUDIO_PACKETIZED 1
#define PAYLOAD_VIDEO 2
#define PAYLOAD_OTHER 3  /* ?? */

struct _PayloadType
{
	int type;
	int clock_rate;
	char bits_per_sample;		/* in case of continuous audio data */
	char *zero_pattern;
	int pattern_length;
	/* other useful information for the application*/
	int normal_bitrate;	/*in bit/s */
	char *mime_type;
	char *recv_fmtp; /* various format parameters for the incoming stream */
	char *send_fmtp; /* various format parameters for the outgoing stream */
	int flags;
	void *user_data;
};

#ifndef PayloadType_defined
#define PayloadType_defined
typedef struct _PayloadType PayloadType;
#endif

#define payload_type_set_flag(pt,flag) (pt)->flags|=((int)flag)
#define payload_type_unset_flag(pt,flag) (pt)->flags&=(~(int)flag)
#define payload_type_get_flags(pt)	(pt)->flags

#define RTP_PROFILE_MAX_PAYLOADS 128

struct _RtpProfile
{
	char *name;
	PayloadType *payload[RTP_PROFILE_MAX_PAYLOADS];
};


typedef struct _RtpProfile RtpProfile;

#ifdef __cplusplus
extern "C"{
#endif
PayloadType *payload_type_new(void);
PayloadType *payload_type_clone(PayloadType *payload);
void payload_type_destroy(PayloadType *pt);
void payload_type_set_recv_fmtp(PayloadType *pt, const char *fmtp);
void payload_type_set_send_fmtp(PayloadType *pt, const char *fmtp);

/*parses a fmtp string such as "profile=0;level=10", finds the value matching parameter
param_name, and writes it into result. Returns TRUE if the parameter was found. */
bool_t fmtp_get_value(const char *fmtp, const char *param_name, char *result, size_t result_len);

VAR_DECLSPEC RtpProfile av_profile;

#ifdef __cplusplus
}
#endif


#define payload_type_set_user_data(pt,p)	(pt)->user_data=(p)
#define payload_type_get_user_data(pt)		((pt)->user_data)



#define rtp_profile_get_name(profile) 	(const char*)((profile)->name)

#ifdef __cplusplus
extern "C"{
#endif

void rtp_profile_set_payload(RtpProfile *prof, int idx, PayloadType *pt);

#define rtp_profile_clear_payload(profile,index)	rtp_profile_set_payload(profile,index,NULL)	

/* I prefer have this function inlined because it is very often called in the code */
static inline PayloadType * rtp_profile_get_payload(RtpProfile *prof, int idx){
	if (idx<0 || idx>=RTP_PROFILE_MAX_PAYLOADS) {
		return NULL;
	}
	return prof->payload[idx];
}
void rtp_profile_clear_all(RtpProfile *prof);
void rtp_profile_set_name(RtpProfile *prof, const char *name);
PayloadType * rtp_profile_get_payload_from_mime(RtpProfile *profile,const char *mime);
PayloadType * rtp_profile_get_payload_from_rtpmap(RtpProfile *profile, const char *rtpmap);
int rtp_profile_get_payload_number_from_mime(RtpProfile *profile,const char *mime);
int rtp_profile_get_payload_number_from_rtpmap(RtpProfile *profile, const char *rtpmap);
int rtp_profile_find_payload_number(RtpProfile *prof,const char *mime,int rate);
PayloadType * rtp_profile_find_payload(RtpProfile *prof,const char *mime,int rate);
int rtp_profile_move_payload(RtpProfile *prof,int oldpos,int newpos);

RtpProfile * rtp_profile_new(const char *name);
/* clone a profile, payload are not cloned */
RtpProfile * rtp_profile_clone(RtpProfile *prof);


/*clone a profile and its payloads (ie payload type are newly allocated, not reusing payload types of the reference profile) */
RtpProfile * rtp_profile_clone_full(RtpProfile *prof);
/* frees the profile and all its PayloadTypes*/
void rtp_profile_destroy(RtpProfile *prof);
#ifdef __cplusplus
}
#endif

/* some payload types */
/* audio */
VAR_DECLSPEC PayloadType payload_type_pcmu8000;
VAR_DECLSPEC PayloadType payload_type_pcma8000;
VAR_DECLSPEC PayloadType payload_type_pcm8000;
VAR_DECLSPEC PayloadType payload_type_lpc1016;
VAR_DECLSPEC PayloadType payload_type_g729;
VAR_DECLSPEC PayloadType payload_type_g7231;
VAR_DECLSPEC PayloadType payload_type_gsm;
VAR_DECLSPEC PayloadType payload_type_lpc1015;
VAR_DECLSPEC PayloadType payload_type_speex_nb;
VAR_DECLSPEC PayloadType payload_type_speex_wb;
VAR_DECLSPEC PayloadType payload_type_ilbc;
VAR_DECLSPEC PayloadType payload_type_amr;
VAR_DECLSPEC PayloadType payload_type_amrwb;
VAR_DECLSPEC PayloadType payload_type_truespeech;
VAR_DECLSPEC PayloadType payload_type_evrc0;

/* video */
VAR_DECLSPEC PayloadType payload_type_mpv;
VAR_DECLSPEC PayloadType payload_type_h261;
VAR_DECLSPEC PayloadType payload_type_h263;
VAR_DECLSPEC PayloadType payload_type_h263_1998;
VAR_DECLSPEC PayloadType payload_type_h263_2000;
VAR_DECLSPEC PayloadType payload_type_mp4v;
VAR_DECLSPEC PayloadType payload_type_theora;

/* telephone-event */
VAR_DECLSPEC PayloadType payload_type_telephone_event;


#endif
