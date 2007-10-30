/*
  The mediastreamer library aims at providing modular media processing and I/O
        for linphone, but also for any telephony application.
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


#include "mediastreamer2/mediastream.h"
#include "mediastreamer2/msfilter.h"
#include "mediastreamer2/msvideo.h"
#include "mediastreamer2/msrtp.h"
#include "mediastreamer2/msv4l.h"

#ifdef HAVE_CONFIG_H
#include "mediastreamer-config.h"
#endif

extern RtpSession * create_duplex_rtpsession(RtpProfile *profile, int locport,const char *remip,int remport,int payload,int jitt_comp);

#define MAX_RTP_SIZE	UDP_MAX_SIZE

/* this code is not part of the library itself, it is part of the mediastream program */
void video_stream_free (VideoStream * stream)
{
	if (stream->session!=NULL)
		rtp_session_destroy(stream->session);
	if (stream->rtprecv != NULL)
		ms_filter_destroy (stream->rtprecv);
	if (stream->rtpsend!=NULL) 
		ms_filter_destroy (stream->rtpsend);
	if (stream->source != NULL)
		ms_filter_destroy (stream->source);
	if (stream->output != NULL)
		ms_filter_destroy (stream->output);
	if (stream->decoder != NULL)
		ms_filter_destroy (stream->decoder);
	if (stream->encoder != NULL)
		ms_filter_destroy (stream->encoder);
	if (stream->pixconv!=NULL)
		ms_filter_destroy(stream->pixconv);
	if (stream->tee!=NULL)
		ms_filter_destroy(stream->tee);
	if (stream->sizeconv!=NULL)
		ms_filter_destroy(stream->sizeconv);
	if (stream->ticker != NULL)
		ms_ticker_destroy (stream->ticker);
	ms_free (stream);
}

/*this function must be called from the MSTicker thread:
it replaces one filter by another one.
This is a dirty hack that works anyway.
It would be interesting to have something that does the job
simplier within the MSTicker api
*/
void video_stream_change_decoder(VideoStream *stream, int payload){
	RtpSession *session=stream->session;
	RtpProfile *prof=rtp_session_get_profile(session);
	PayloadType *pt=rtp_profile_get_payload(prof,payload);
	if (pt!=NULL){
		MSFilter *dec=ms_filter_create_decoder(pt->mime_type);
		if (dec!=NULL){
			ms_filter_unlink(stream->rtprecv, 0, stream->decoder, 0);
			ms_filter_unlink(stream->decoder,0,stream->sizeconv,0);
			ms_filter_postprocess(stream->decoder);
			ms_filter_destroy(stream->decoder);
			stream->decoder=dec;
			if (pt->recv_fmtp!=NULL)
				ms_filter_call_method(stream->decoder,MS_FILTER_SET_FMTP,(void*)pt->recv_fmtp);
			ms_filter_link (stream->rtprecv, 0, stream->decoder, 0);
			ms_filter_link (stream->decoder,0 , stream->sizeconv, 0);
			ms_filter_preprocess(stream->decoder,stream->ticker);
			
		}else{
			ms_warning("No decoder found for %s",pt->mime_type);
		}
	}else{
		ms_warning("No payload defined with number %i",payload);
	}
}

void video_stream_iterate(VideoStream *stream){
}

static void payload_type_changed(RtpSession *session, unsigned long data){
	VideoStream *stream=(VideoStream*)data;
	int pt=rtp_session_get_recv_payload_type(stream->session);
	video_stream_change_decoder(stream,pt);
}

VideoStream *
video_stream_start (RtpProfile *profile, int locport, const char *remip, int remport,int payload, int jitt_comp,  const char *device)
{
	VideoStream *stream = ms_new0 (VideoStream, 1);
	PayloadType *pt;
	MSPixFmt format;
	MSVideoSize vsize=MS_VIDEO_SIZE_CIF;
	float fps=15;

	pt=rtp_profile_get_payload(profile,payload);
	if (pt==NULL){
		video_stream_free(stream);
		ms_error("videostream.c: undefined payload type.");
		return NULL;
	}
	stream->session=create_duplex_rtpsession(profile,locport,remip,remport,payload,jitt_comp);
	rtp_session_enable_adaptive_jitter_compensation(stream->session,TRUE);
	rtp_session_signal_connect(stream->session,"payload_type_changed",
			(RtpCallback)payload_type_changed,(unsigned long)stream);

	/* creates two rtp filters to recv send streams (remote part) */
	rtp_session_set_recv_buf_size(stream->session,MAX_RTP_SIZE);
	stream->rtpsend =ms_filter_new(MS_RTP_SEND_ID);
	if (remport>0) ms_filter_call_method(stream->rtpsend,MS_RTP_SEND_SET_SESSION,stream->session);
	
	stream->rtprecv = ms_filter_new (MS_RTP_RECV_ID);
	ms_filter_call_method(stream->rtprecv,MS_RTP_RECV_SET_SESSION,stream->session);

	/* creates the filters */
	stream->source = ms_filter_new(MS_V4L_ID);
	stream->tee = ms_filter_new(MS_TEE_ID);
	stream->sizeconv = ms_filter_new(MS_SIZE_CONV_ID);
	stream->output=ms_filter_new(MS_VIDEO_OUT_ID);

	stream->encoder=ms_filter_create_encoder(pt->mime_type);
	stream->decoder=ms_filter_create_decoder(pt->mime_type);
	if ((stream->encoder==NULL) || (stream->decoder==NULL)){
		/* big problem: we have not a registered codec for this payload...*/
		ms_error("videostream.c: No codecs available for payload %i:%s.",payload,pt->mime_type);
		video_stream_free(stream);
		return NULL;
	}
	
	if (pt->normal_bitrate>0){
		ms_message("Limiting bitrate of video encoder to %i bits/s",pt->normal_bitrate);
		ms_filter_call_method(stream->encoder,MS_FILTER_SET_BITRATE,&pt->normal_bitrate);
	}
	/* set parameters to the encoder and decoder*/
	if (pt->send_fmtp){
		ms_filter_call_method(stream->encoder,MS_FILTER_ADD_FMTP,pt->send_fmtp);
		ms_filter_call_method(stream->decoder,MS_FILTER_ADD_FMTP,pt->send_fmtp);
	}
	ms_filter_call_method(stream->encoder,MS_FILTER_GET_VIDEO_SIZE,&vsize);
	ms_filter_call_method(stream->encoder,MS_FILTER_GET_FPS,&fps);
	ms_message("Setting vsize=%ix%i, fps=%f",vsize.width,vsize.height,fps);
	/* configure the filters */
	ms_filter_call_method(stream->source,MS_FILTER_SET_FPS,&fps);
	ms_filter_call_method(stream->source,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	ms_filter_call_method_noarg(stream->source,MS_V4L_START);
	/* get the output format for webcam reader */
	ms_filter_call_method(stream->source,MS_FILTER_GET_PIX_FMT,&format);
	if (format==MS_MJPEG){
		stream->pixconv=ms_filter_new(MS_MJPEG_DEC_ID);
	}else{
		stream->pixconv = ms_filter_new(MS_PIX_CONV_ID);
		/*set it to the pixconv */
		ms_filter_call_method(stream->pixconv,MS_FILTER_SET_PIX_FMT,&format);
		ms_filter_call_method(stream->pixconv,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	}
	/*force the decoder to output YUV420P */
	format=MS_YUV420P;
	ms_filter_call_method(stream->decoder,MS_FILTER_SET_PIX_FMT,&format);
	/*ask the size-converter to always output CIF */
	vsize=MS_VIDEO_SIZE_CIF;
	ms_filter_call_method(stream->sizeconv,MS_FILTER_SET_PIX_FMT,&format);
	ms_filter_call_method(stream->sizeconv,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	ms_filter_call_method(stream->output,MS_FILTER_SET_PIX_FMT,&format);

	if (pt->recv_fmtp!=NULL)
		ms_filter_call_method(stream->decoder,MS_FILTER_SET_FMTP,(void*)pt->recv_fmtp);

	/* and then connect all */
	ms_filter_link (stream->source, 0, stream->pixconv, 0);
	ms_filter_link (stream->pixconv, 0, stream->tee, 0);
	ms_filter_link (stream->tee, 0 ,stream->encoder, 0 );
	ms_filter_link (stream->encoder,0, stream->rtpsend,0);
	
	ms_filter_link (stream->rtprecv, 0, stream->decoder, 0);
	ms_filter_link (stream->decoder,0 , stream->sizeconv, 0);
	ms_filter_link (stream->sizeconv, 0, stream->output, 0);
	/* the source video must be send for preview */
	ms_filter_link(stream->tee,1,stream->output,1);

	/* create the ticker */
	stream->ticker = ms_ticker_new(); 
	/* attach it the graph */
	ms_ticker_attach (stream->ticker, stream->source);
	return stream;
}



void
video_stream_stop (VideoStream * stream)
{

	ms_ticker_detach(stream->ticker,stream->source);
	ms_filter_call_method_noarg(stream->source,MS_V4L_STOP);

	rtp_stats_display(rtp_session_get_stats(stream->session),"Video session's RTP statistics");
	
	ms_filter_unlink(stream->source,0,stream->pixconv,0);
	ms_filter_unlink(stream->pixconv,0,stream->tee,0);
	ms_filter_unlink(stream->tee,0,stream->encoder,0);
	ms_filter_unlink(stream->encoder, 0, stream->rtpsend,0);
	ms_filter_unlink(stream->rtprecv, 0, stream->decoder, 0);
	ms_filter_unlink(stream->decoder,0,stream->sizeconv,0);
	ms_filter_unlink(stream->sizeconv,0,stream->output,0);
	ms_filter_unlink(stream->tee,1,stream->output,1);
	video_stream_free (stream);
}


void video_stream_set_rtcp_information(VideoStream *st, const char *cname, const char *tool){
	if (st->session!=NULL){
		rtp_session_set_source_description(st->session,cname,NULL,NULL,NULL,NULL,tool,
											"This is free software (GPL) !");
	}
}



VideoStream * video_preview_start(const char *device){
	VideoStream *stream = ms_new0 (VideoStream, 1);
	MSPixFmt format;
	MSVideoSize vsize;
	vsize.width=MS_VIDEO_SIZE_CIF_W;
	vsize.height=MS_VIDEO_SIZE_CIF_H;

	/* creates the filters */
	stream->source = ms_filter_new(MS_V4L_ID);
	stream->output = ms_filter_new(MS_VIDEO_OUT_ID);

	/* configure the filters */
	ms_filter_call_method_noarg(stream->source,MS_V4L_START);
	ms_filter_call_method(stream->source,MS_FILTER_GET_PIX_FMT,&format);
	ms_filter_call_method(stream->source,MS_FILTER_GET_VIDEO_SIZE,&vsize);
	
	if (format==MS_MJPEG){
		stream->pixconv=ms_filter_new(MS_MJPEG_DEC_ID);
	}else{
		stream->pixconv=ms_filter_new(MS_PIX_CONV_ID);
		ms_filter_call_method(stream->pixconv,MS_FILTER_SET_PIX_FMT,&format);
		ms_filter_call_method(stream->pixconv,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	}
	format=MS_YUV420P;
	ms_filter_call_method(stream->output,MS_FILTER_SET_PIX_FMT,&format);
	ms_filter_call_method(stream->output,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	/* and then connect all */
	ms_filter_link(stream->source,0, stream->pixconv,0);
	ms_filter_link(stream->pixconv,0,stream->output,0);
	/* create the ticker */
	stream->ticker = ms_ticker_new(); 
	ms_ticker_attach (stream->ticker, stream->source);
	return stream;
}

void video_preview_stop(VideoStream *stream){
	ms_ticker_detach(stream->ticker, stream->source);
	ms_filter_call_method_noarg(stream->source,MS_V4L_STOP);
	ms_filter_unlink(stream->source,0,stream->pixconv,0);
	ms_filter_unlink(stream->pixconv,0,stream->output,0);
	
	video_stream_free(stream);
}


VideoStream *
video_stream_recv_only_start (RtpProfile *profile, int locport, const char *remip, int remport,int payload, int jitt_comp,  const char *device)
{
	VideoStream *stream = ms_new0 (VideoStream, 1);
	PayloadType *pt;
	MSPixFmt format;
	MSVideoSize vsize=MS_VIDEO_SIZE_CIF;
	float fps=15;

	pt=rtp_profile_get_payload(profile,payload);
	if (pt==NULL){
		video_stream_free(stream);
		ms_error("videostream.c: undefined payload type.");
		return NULL;
	}
	stream->session=create_duplex_rtpsession(profile,locport,remip,remport,payload,jitt_comp);
	rtp_session_enable_adaptive_jitter_compensation(stream->session,TRUE);
	rtp_session_signal_connect(stream->session,"payload_type_changed",
			(RtpCallback)payload_type_changed,(unsigned long)stream);

	/* creates rtp filters to recv streams */
	rtp_session_set_recv_buf_size(stream->session,MAX_RTP_SIZE);
	stream->rtprecv = ms_filter_new (MS_RTP_RECV_ID);
	ms_filter_call_method(stream->rtprecv,MS_RTP_RECV_SET_SESSION,stream->session);

	/* creates the filters */
	stream->sizeconv = ms_filter_new(MS_SIZE_CONV_ID);
	stream->output=ms_filter_new(MS_VIDEO_OUT_ID);
	stream->decoder=ms_filter_create_decoder(pt->mime_type);
	if (stream->decoder==NULL){
		/* big problem: we have not a registered codec for this payload...*/
		ms_error("videostream.c: No codecs available for payload %i:%s.",payload,pt->mime_type);
		video_stream_free(stream);
		return NULL;
	}

	/*force the decoder to output YUV420P */
	format=MS_YUV420P;
	ms_filter_call_method(stream->decoder,MS_FILTER_SET_PIX_FMT,&format);
	/*ask the size-converter to always output QVGA */
	vsize=MS_VIDEO_SIZE_QVGA;
	ms_message("Setting output vsize=%ix%i",vsize.width,vsize.height);
	ms_filter_call_method(stream->sizeconv,MS_FILTER_SET_PIX_FMT,&format);
	ms_filter_call_method(stream->sizeconv,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	ms_filter_call_method(stream->output,MS_FILTER_SET_PIX_FMT,&format);
	ms_filter_call_method(stream->output,MS_FILTER_SET_VIDEO_SIZE,&vsize);

	if (pt->recv_fmtp!=NULL) {
		ms_message("pt->recv_fmtp: %s", pt->recv_fmtp);
		ms_filter_call_method(stream->decoder,MS_FILTER_SET_FMTP,(void*)pt->recv_fmtp);
	}

	/* and then connect all */
	ms_filter_link (stream->rtprecv, 0, stream->decoder, 0);
	ms_filter_link (stream->decoder,0 , stream->sizeconv, 0);
	ms_filter_link (stream->sizeconv, 0, stream->output, 0);

	/* create the ticker */
	stream->ticker = ms_ticker_new(); 
	/* attach it the graph */
	ms_ticker_attach (stream->ticker, stream->rtprecv);
	return stream;
}

void
video_stream_recv_only_stop (VideoStream * stream)
{
	ms_ticker_detach(stream->ticker, stream->rtprecv);
	rtp_stats_display(rtp_session_get_stats(stream->session),"Video session's RTP statistics");
	ms_filter_unlink(stream->rtprecv, 0, stream->decoder, 0);
	ms_filter_unlink(stream->decoder,0,stream->sizeconv,0);
	ms_filter_unlink(stream->sizeconv,0,stream->output,0);
	video_stream_free (stream);
}


VideoStream * video_stream_send_only_start(RtpProfile *profile, int locport, const char *remip, int remport, int payload, int jitt_comp, const char *device)
{
	VideoStream *stream = ms_new0 (VideoStream, 1);
	PayloadType *pt;
	MSPixFmt format;
	MSVideoSize vsize=MS_VIDEO_SIZE_CIF;
	float fps=15;
	
	pt=rtp_profile_get_payload(profile,payload);
	if (pt==NULL){
		video_stream_free(stream);
		ms_error("videostream.c: undefined payload type.");
		return NULL;
	}
	stream->session=create_duplex_rtpsession(profile,locport,remip,remport,payload,jitt_comp);
	rtp_session_enable_adaptive_jitter_compensation(stream->session, TRUE);
	
	/* creates rtp filter to send streams (remote part) */
	rtp_session_set_recv_buf_size(stream->session,MAX_RTP_SIZE);
	stream->rtpsend =ms_filter_new(MS_RTP_SEND_ID);
	if (remport>0) ms_filter_call_method(stream->rtpsend,MS_RTP_SEND_SET_SESSION,stream->session);
	

	/* creates the filters */
	stream->source = ms_filter_new(MS_V4L_ID);
	stream->pixconv= ms_filter_new(MS_PIX_CONV_ID);
	stream->encoder=ms_filter_create_encoder(pt->mime_type);
	if ((stream->encoder==NULL)){
		/* big problem: we have not a registered codec for this payload...*/
		video_stream_free(stream);
		ms_error("videostream.c: No codecs available for payload %i.",payload);
		return NULL;
	}

	/* configure the filters */
	if (pt->send_fmtp)
		ms_filter_call_method(stream->encoder,MS_FILTER_ADD_FMTP,pt->send_fmtp);
	ms_filter_call_method(stream->encoder,MS_FILTER_SET_BITRATE,&pt->normal_bitrate);
	ms_filter_call_method(stream->encoder,MS_FILTER_GET_FPS,&fps);
	ms_filter_call_method(stream->encoder,MS_FILTER_GET_VIDEO_SIZE,&vsize);

	ms_filter_call_method(stream->source,MS_FILTER_SET_FPS,&fps);
	ms_filter_call_method(stream->source,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	ms_filter_call_method_noarg(stream->source,MS_V4L_START);
	/* get the output format for webcam reader */
	ms_filter_call_method(stream->source,MS_FILTER_GET_PIX_FMT,&format);
	/*set it to the pixconv */
	ms_filter_call_method(stream->pixconv,MS_FILTER_SET_PIX_FMT,&format);
	ms_filter_call_method(stream->pixconv,MS_FILTER_SET_VIDEO_SIZE,&vsize);
	
	ms_message("vsize=%ix%i, fps=%f, send format: %s, capture format: %d, bitrate: %d",
			vsize.width,vsize.height,fps,pt->send_fmtp,format, pt->normal_bitrate);

	/* and then connect all */
	ms_filter_link (stream->source, 0, stream->pixconv, 0);
	ms_filter_link (stream->pixconv, 0, stream->encoder, 0);
	ms_filter_link (stream->encoder,0, stream->rtpsend,0);

	/* create the ticker */
	stream->ticker = ms_ticker_new(); 
	/* attach it the graph */
	ms_ticker_attach (stream->ticker, stream->source);
	return stream;
}

void video_stream_send_only_stop(VideoStream *stream){
	ms_ticker_detach (stream->ticker, stream->source);
	ms_filter_call_method_noarg(stream->source,MS_V4L_STOP);
	ms_filter_unlink(stream->source,0,stream->pixconv,0);
	ms_filter_unlink(stream->pixconv,0,stream->encoder,0);
	ms_filter_unlink(stream->encoder,0,stream->rtpsend,0);
	
	video_stream_free(stream);
}
