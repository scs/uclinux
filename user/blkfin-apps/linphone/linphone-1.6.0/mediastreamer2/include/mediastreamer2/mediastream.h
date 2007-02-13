/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/


#ifndef MEDIASTREAM_H
#define MEDIASTREAM_H

#include "msfilter.h"
#include "msticker.h"
#include "mssndcard.h"
#include "ortp/ortp.h"

struct _AudioStream
{
	MSTicker *ticker;
	RtpSession *session;
	MSFilter *soundread;
	MSFilter *soundwrite;
	MSFilter *encoder;
	MSFilter *decoder;
	MSFilter *rtprecv;
	MSFilter *rtpsend;
	MSFilter *dtmfgen;
	MSFilter *ec;/*echo canceler*/
};

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _AudioStream AudioStream;

struct _RingStream
{
	MSTicker *ticker;
	MSFilter *source;
	MSFilter *sndwrite;
};

typedef struct _RingStream RingStream;

/* start a thread that does sampling->encoding->rtp_sending|rtp_receiving->decoding->playing */
AudioStream *audio_stream_start (RtpProfile * prof, int locport, const char *remip,
				 int remport, int profile, int jitt_comp, bool_t echo_cancel);

AudioStream *audio_stream_start_with_sndcards(RtpProfile * prof, int locport, const char *remip4, int remport, int profile, int jitt_comp, MSSndCard *playcard, MSSndCard *captcard, bool_t echocancel);

AudioStream *audio_stream_start_with_files (RtpProfile * prof, int locport,
					    const char *remip, int remport,
					    int pt, int jitt_comp,
					    const char * infile,  const char * outfile);

void audio_stream_play(AudioStream *st, const char *name);
void audio_stream_record(AudioStream *st, const char *name);

void audio_stream_set_rtcp_information(AudioStream *st, const char *cname, const char *tool);


/* stop the above process*/
void audio_stream_stop (AudioStream * stream);

RingStream *ring_start (const char * file, int interval, MSSndCard *sndcard);
RingStream *ring_start_with_cb(const char * file, int interval, MSSndCard *sndcard, MSFilterNotifyFunc func, void * user_data);
void ring_stop (RingStream * stream);


/* send a dtmf */
int audio_stream_send_dtmf (AudioStream * stream, char dtmf);

void audio_stream_set_default_card(int cardindex);


/*****************
  Video Support
 *****************/


struct _VideoStream
{
	MSTicker *ticker;
	RtpSession *session;
	MSFilter *source;
	MSFilter *predec;
	MSFilter *pixconv;
	MSFilter *tee;
	MSFilter *sizeconv;
	MSFilter *output;
	MSFilter *encoder;
	MSFilter *decoder;
	MSFilter *rtprecv;
	MSFilter *rtpsend;
};


typedef struct _VideoStream VideoStream;

VideoStream *video_stream_start(RtpProfile *profile, int locport, const char *remip, int remport, int payload, int jitt_comp, const char *device);
void video_stream_set_rtcp_information(VideoStream *st, const char *cname, const char *tool);
/*function to call periodically to handle various events */
void video_stream_iterate(VideoStream *stream);
void video_stream_stop (VideoStream * stream);

VideoStream * video_preview_start(const char *device);
void video_preview_stop(VideoStream *stream);

VideoStream * video_stream_send_only_start(RtpProfile *profile, int locport, const char *remip, int remport, int payload, const char *device);

void video_stream_send_only_stop(VideoStream *stream);

#ifdef __cplusplus
}
#endif


#endif
