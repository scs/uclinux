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

#include <ffmpeg/avcodec.h>
#include "mediastreamer2/msfilter.h"
#include "mediastreamer2/msvideo.h"
#include "mediastreamer2/msticker.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>			/* ntohl(3) */
#endif

#include "rfc2429.h"

static bool_t avcodec_initialized=FALSE;

void ms_ffmpeg_check_init(){
	if(!avcodec_initialized){
		avcodec_init();
		avcodec_register_all();
		avcodec_initialized=TRUE;
	}
}

typedef struct EncState{
	AVCodecContext av_context;
	AVCodec *av_codec;
	mblk_t *comp_buf;
	int mtu;	/* network maximum transmission unit in bytes */
}EncState;

static int enc_set_fps(MSFilter *f, void *arg){
	EncState *s=(EncState*)f->data;
	float fps=*(float*)arg;
	s->av_context.time_base.num = (int)fps;
	s->av_context.time_base.den = 1;
	s->av_context.gop_size=(int)fps*5; /*emit I frame every 5 seconds*/
	return 0;
}

static int enc_set_vsize(MSFilter *f,void *arg){
	EncState *s=(EncState*)f->data;
	MSVideoSize *vsize=(MSVideoSize*)arg;
	s->av_context.width=vsize->width;
	s->av_context.height=vsize->height;
	return 0;
}

static int enc_set_br(MSFilter *f, void *arg){
	/*setting bitrate works too bad: I don't understand how it works in ffmpeg*/
	/*
	EncState *s=(EncState*)f->data;
	int bitrate=*(int*)arg;
	if (bitrate>0){
		s->av_context.bit_rate=bitrate;
		ms_message("setting output bitrate to %i",bitrate);
	}
	*/
	return 0;
}

static int enc_set_fmtp(MSFilter *f,void *arg){
	EncState *s=(EncState*)f->data;
	const char *fmtp=(const char*)arg;
	char val[10];
	if (fmtp_get_value(fmtp,"profile",val,sizeof(val))){
		if (atoi(val)==0){
			/*if profile=0, use simple H263 */
			ms_message("using H263 encode because profile is 0");
			s->av_context.flags=0;
			s->av_codec=avcodec_find_encoder(CODEC_ID_H263);
		}
	}
	return 0;
}

static void enc_init(MSFilter *f)
{
	EncState *s=ms_new(EncState,1);
	AVCodecContext *c=&s->av_context;
	float fps=15;
	f->data=s;
	ms_ffmpeg_check_init();
	avcodec_get_context_defaults(c);
	/* put codec parameters */
	c->bit_rate=20000;
	c->width = MS_VIDEO_SIZE_CIF_W;  
	c->height = MS_VIDEO_SIZE_CIF_H;
	enc_set_fps(f,&fps);
	c->gop_size = 30; /* emit one intra frame every x frames */
	s->mtu=1400;
	/* we don't use the rtp_callback but use rtp_mode that forces ffmpeg to insert
	Start Codes as much as possible in the bitstream */
	c->rtp_mode = 1;
	c->rtp_payload_size = s->mtu/2;
	c->pix_fmt=PIX_FMT_YUV420P;
	c->flags|=CODEC_FLAG_H263P_UMV;
	c->flags|=CODEC_FLAG_H263P_AIC;
	c->flags|=CODEC_FLAG_H263P_SLICE_STRUCT;
	/*
	c->flags|=CODEC_FLAG_OBMC;
	c->flags|=CODEC_FLAG_AC_PRED;
	*/
	s->av_codec=avcodec_find_encoder(CODEC_ID_H263P);
	s->comp_buf=allocb(32000,0);
}


static void enc_uninit(MSFilter  *f){
	EncState *s=(EncState*)f->data;
	if (s->comp_buf!=NULL)	freemsg(s->comp_buf);
	ms_free(s);
}

static void enc_set_rc(EncState *s, AVCodecContext *c){
	int factor=c->width/MS_VIDEO_SIZE_QCIF_W;
	c->rc_min_rate=0;
	c->bit_rate=400; /* this value makes around 100kbit/s at QCIF=2 */
	c->rc_max_rate=c->bit_rate+1;
	c->rc_buffer_size=20000*factor;	/* food recipe */
}

static void enc_preprocess(MSFilter *f){
	EncState *s=(EncState*)f->data;
	int error;
	AVCodecContext *c=&s->av_context;
	if (0) enc_set_rc(s,c);
	error=avcodec_open(&s->av_context, s->av_codec);
	if (error!=0) {
		ms_error("avcodec_open() failed: %i",error);
		return;
	}
	ms_debug("image format is %i.",s->av_context.pix_fmt);
}

static void enc_postprocess(MSFilter *f){
	EncState *s=(EncState*)f->data;
	if (s->av_context.codec!=NULL){
		avcodec_close(&s->av_context);
		s->av_context.codec=NULL;
	}
}

static void generate_packets(MSFilter *f, EncState *s, mblk_t *frame, uint32_t timestamp, uint8_t *psc, uint8_t *end, bool_t last_packet){
	mblk_t *packet;
	int len=end-psc;
	
	packet=dupb(frame);	
	packet->b_rptr=psc;
	packet->b_wptr=end;
	/*ms_message("generating packet of size %i",end-psc);*/
	rfc2429_set_P(psc,1);
	mblk_set_timestamp_info(packet,timestamp);

	
	if (len>s->mtu){
		/*need to slit the packet using "follow-on" packets */
		/*compute the number of packets need (rounded up)*/
		int num=(len+s->mtu-1)/s->av_context.rtp_payload_size;
		int i;
		uint8_t *pos;
		/*adjust the first packet generated*/
		pos=packet->b_wptr=packet->b_rptr+s->mtu;
		ms_queue_put(f->outputs[0],packet);
		ms_debug("generating %i follow-on packets",num);
		for (i=1;i<num;++i){
			mblk_t *header;
			packet=dupb(frame);
			packet->b_rptr=pos;
			pos=packet->b_wptr=MIN(pos+s->mtu,end);
			header=allocb(2,0);
			header->b_wptr[0]=0;
			header->b_wptr[1]=0;
			header->b_wptr+=2;
			/*no P bit is set */
			header->b_cont=packet;
			packet=header;
			mblk_set_timestamp_info(packet,timestamp);
			ms_queue_put(f->outputs[0],packet);
		}
	}else ms_queue_put(f->outputs[0],packet);
	/* the marker bit is set on the last packet, if any.*/
	mblk_set_marker_info(packet,last_packet);
}

/* returns the last psc position just below packet_size */
static uint8_t *get_psc(uint8_t *begin,uint8_t *end, int packet_size){
	int i;
	uint8_t *ret=NULL;
	uint8_t *p;
	if (begin==end) return NULL;
	for(i=1,p=begin+1;p<end && i<packet_size;++i,++p){
		if (p[-1]==0 && p[0]==0){
			ret=p-1;
		}
		p++;/* to skip possible 0 after the PSC that would make a double detection */
	}
	return ret;
}

static void split_and_send(MSFilter *f, EncState *s, mblk_t *frame){
	uint8_t *lastpsc;
	uint8_t *psc;
	uint32_t timestamp=f->ticker->time*90LL;
	
	ms_debug("processing frame of size %i",frame->b_wptr-frame->b_rptr);
	lastpsc=frame->b_rptr;
	while(1){
		psc=get_psc(lastpsc+2,frame->b_wptr,s->mtu);
		if (psc!=NULL){
			generate_packets(f,s,frame,timestamp,lastpsc,psc,FALSE);
			lastpsc=psc;
		}else break;
	}
	
	/* send the end of frame */
	generate_packets(f,s,frame, timestamp,lastpsc,frame->b_wptr,TRUE);
}

static void process_frame(MSFilter *f, mblk_t *inm){
	EncState *s=(EncState*)f->data;
	AVFrame pict;
	AVCodecContext *c=&s->av_context;
	int error;
	
	mblk_t *comp_buf=s->comp_buf;
	int comp_buf_sz=comp_buf->b_datap->db_lim-comp_buf->b_datap->db_base;
	/* convert image if necessary */
	avcodec_get_frame_defaults(&pict);
	avpicture_fill((AVPicture*)&pict,(uint8_t*)inm->b_rptr,c->pix_fmt,c->width,c->height);
	
	/* timestamp used by ffmpeg, unset here */
	pict.pts=AV_NOPTS_VALUE;
	comp_buf->b_rptr=comp_buf->b_wptr=comp_buf->b_datap->db_base;
	error=avcodec_encode_video(c, (uint8_t*)s->comp_buf->b_wptr,comp_buf_sz, &pict);
	if (error<=0) ms_warning("ms_AVencoder_process: error %i.",error);
	else{
		comp_buf->b_wptr+=error;
		split_and_send(f,s,comp_buf);
	}
	freemsg(inm);
}

static void enc_process(MSFilter *f){
	mblk_t *inm;
	EncState *s=(EncState*)f->data;
	if (s->av_context.codec==NULL) {
		ms_queue_flush(f->inputs[0]);
		return;
	}
	while((inm=ms_queue_get(f->inputs[0]))!=0){
		process_frame(f,inm);
	}
}

static MSFilterMethod methods[]={
	{	MS_FILTER_SET_FPS	,	enc_set_fps	},
	{	MS_FILTER_SET_VIDEO_SIZE ,	enc_set_vsize },
	{	MS_FILTER_SET_FMTP	,	enc_set_fmtp },
	{	MS_FILTER_SET_BITRATE	,	enc_set_br	},
	{	0										,	NULL	}
};

MSFilterDesc ms_h263_enc_desc={
	.id=MS_H263_ENC_ID,
	.name="MSH263Enc",
	.text="A video H.263 encoder using ffmpeg library.",
	.category=MS_FILTER_ENCODER,
	.enc_fmt="H263-1998",
	.ninputs=1, /*MS_YUV420P is assumed on this input */
	.noutputs=1,
	.init=enc_init,
	.preprocess=enc_preprocess,
	.process=enc_process,
	.postprocess=enc_postprocess,
	.uninit=enc_uninit,
	.methods=methods
};

MS_FILTER_DESC_EXPORT(ms_h263_enc_desc)
