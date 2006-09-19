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

#include "mediastreamer2/msfilter.h"
#include "mediastreamer2/msticker.h"
#include "mediastreamer2/msvideo.h"

#include <theora/theora.h>

typedef struct EncState{
	theora_state tstate;
	theora_info tinfo;
	yuv_buffer yuv;
	mblk_t *header;
	mblk_t *comment;
	mblk_t *tables;
	uint frame_count;
	uint mtu;
} EncState;

static void enc_init(MSFilter *f){
	EncState *s=ms_new(EncState,1);
	theora_info_init(&s->tinfo);
	s->tinfo.width=MS_VIDEO_SIZE_CIF_W;
	s->tinfo.height=MS_VIDEO_SIZE_CIF_H;
	s->tinfo.frame_width=MS_VIDEO_SIZE_CIF_W;
	s->tinfo.frame_height=MS_VIDEO_SIZE_CIF_H;
	s->tinfo.offset_x=0;
	s->tinfo.offset_y=0;
	s->tinfo.target_bitrate=50000;
	s->tinfo.pixelformat=OC_PF_420;
	s->tinfo.fps_numerator=15;
	s->tinfo.fps_denominator=1;
	s->tinfo.aspect_numerator=1;
	s->tinfo.aspect_denominator=1;
	s->tinfo.colorspace=OC_CS_UNSPECIFIED;
	s->tinfo.dropframes_p=0;
	s->tinfo.quick_p=1;
	s->tinfo.keyframe_auto_p=1;
	s->tinfo.keyframe_frequency=64;
	s->tinfo.keyframe_frequency_force=64;
	s->tinfo.keyframe_data_target_bitrate=s->tinfo.target_bitrate*1.2;
	s->tinfo.keyframe_auto_threshold=80;
	s->tinfo.keyframe_mindistance=8;
	s->tinfo.noise_sensitivity=1;
	s->header=NULL;
	s->tables=NULL;
	s->comment=NULL;
	s->mtu=1400-4;
	f->data=s;
}

static void enc_uninit(MSFilter *f){
	EncState *s=(EncState*)f->data;
	ms_free(s);
}

static int enc_set_vsize(MSFilter *f, void*data){
	MSVideoSize *vs=(MSVideoSize*)data;
	EncState *s=(EncState*)f->data;
	s->tinfo.width=vs->width;
	s->tinfo.height=vs->height;
	s->tinfo.frame_width=vs->width;
	s->tinfo.frame_height=vs->height;
	return 0;
}

static int enc_add_attr(MSFilter *f, void*data){
	/*const char *attr=(const char*)data;
	EncState *s=(EncState*)f->data;*/
	return 0;
}

static int enc_set_br(MSFilter *f, void*data){
	int *br=(int*)data;
	EncState *s=(EncState*)f->data;
	s->tinfo.target_bitrate=(*br)/1.2;
	s->tinfo.keyframe_data_target_bitrate=*br;
	return 0;
}


static int enc_set_fps(MSFilter *f, void *data){
	float *fps=(float*)data;
	EncState *s=(EncState*)f->data;
	s->tinfo.fps_numerator=*fps;
	s->tinfo.keyframe_frequency=(*fps)*5;
	s->tinfo.keyframe_frequency_force=(*fps)*5;
	return 0;
}

#define THEORA_RAW_DATA	0
#define THEORA_HEADER_DATA 1
#define THEORA_COMMENT_DATA 2
#define THEORA_TABLES_DATA 3

static inline void payload_header_set(uint8_t *buf, uint32_t ident, uint8_t tdt){
	uint32_t tmp;
	tmp=((ident&0xFFFFFF)<<8)| (tdt&0xff);
	*((uint32_t*)buf)=htonl(tmp);
}

static inline uint32_t payload_header_get_ident(uint8_t *buf){
	uint32_t *tmp=(uint32_t*)buf;
	return (ntohl(*tmp)>>8) & 0xFFFFFF;
}

static inline uint32_t payload_header_get_tdt(uint8_t *buf){
	uint32_t *tmp=(uint32_t*)buf;
	return (ntohl(*tmp)) & 0xFF;
}


static int create_packed_conf(EncState *s){
	ogg_packet p;
	theora_state *tstate=&s->tstate;
	mblk_t *h,*t,*c;
	theora_comment tcom;
	if (theora_encode_header(tstate,&p)!=0){
		ms_error("theora_encode_header() error.");
		return -1;
	}
	h=allocb(p.bytes,0);
	memcpy(h->b_wptr,p.packet,p.bytes);
	h->b_wptr+=p.bytes;
	if (theora_encode_tables(tstate,&p)!=0){
		ms_error("theora_encode_tables error.");
		freemsg(h);
		return -1;
	}
	t=allocb(p.bytes,0);
	memcpy(t->b_wptr,p.packet,p.bytes);
	t->b_wptr+=p.bytes;
	theora_comment_init(&tcom);
	if (tcom.vendor==NULL) tcom.vendor="Xiph";
	if (theora_encode_comment(&tcom,&p)!=0){
		ms_error("theora_encode_tables error.");
		freemsg(h);
		freemsg(t);
		return -1;
	}
	s->header=h;
	s->tables=t;
	s->comment=c=allocb(p.bytes,0);
	memcpy(c->b_wptr,p.packet,p.bytes);
	c->b_wptr+=p.bytes;
	return 0;
}

static void enc_preprocess(MSFilter *f){
	EncState *s=(EncState*)f->data;
	if (theora_encode_init(&s->tstate,&s->tinfo)!=0){
		ms_error("error in theora_encode_init() !");
	}
	s->yuv.y_width=s->tinfo.width;
	s->yuv.y_height=s->tinfo.height;
	s->yuv.y_stride=s->tinfo.width;
	s->yuv.uv_width=s->tinfo.width/2;
	s->yuv.uv_height=s->tinfo.height/2;
	s->yuv.uv_stride=s->tinfo.width/2;
	create_packed_conf(s);
	s->frame_count=0;
}

static void enc_postprocess(MSFilter *f){
	EncState *s=(EncState*)f->data;
	theora_clear(&s->tstate);
	theora_info_clear(&s->tinfo);
	if (s->header) freemsg(s->header);
	if (s->tables) freemsg(s->tables);
	if (s->comment) freemsg(s->comment);
}

static void enc_fill_yuv(yuv_buffer *yuv, mblk_t *im){
	yuv->y=(uint8_t*)im->b_rptr;
	yuv->u=(uint8_t*)im->b_rptr+(yuv->y_stride*yuv->y_height);
	yuv->v=(uint8_t*)yuv->u+(yuv->uv_stride*yuv->uv_height);
}


static void packetize_and_send(MSFilter *f, EncState *s, mblk_t *om, uint32_t timestamp, uint8_t tdt){
	mblk_t *packet;
	mblk_t *h;
	bool_t markbit=FALSE;
	while(om!=NULL){
		if (om->b_wptr-om->b_rptr>=s->mtu){
			packet=dupb(om);
			packet->b_wptr=packet->b_rptr+s->mtu;
			om->b_rptr=packet->b_wptr;
		}else {
			packet=om;
			om=NULL;
			markbit=TRUE;
		}
		h=allocb(4,0);
		payload_header_set((uint8_t*)h->b_wptr,0xdede,tdt);
		h->b_wptr+=4;
		h->b_cont=packet;
		mblk_set_timestamp_info(h,timestamp);
		mblk_set_marker_info(h,markbit);
		ms_debug("sending theora frame of size %i",msgdsize(h));
		ms_queue_put(f->outputs[0],h);
	}
}

static void enc_process(MSFilter *f){
	mblk_t *im,*om;
	ogg_packet op;
	EncState *s=(EncState*)f->data;
	uint timems=f->ticker->time;
	uint32_t timestamp=timems*90;
	while((im=ms_queue_get(f->inputs[0]))!=NULL){
		/*for the firsts frames only send theora packed conf*/
		om=NULL;
		if (s->frame_count<16){
			if (s->frame_count%5==0){
				om=dupmsg(s->header);
				ms_debug("sending theora header");
				packetize_and_send(f,s,om,timestamp,THEORA_HEADER_DATA);
				om=dupmsg(s->tables);
				ms_debug("sending theora tables");
				packetize_and_send(f,s,om,timestamp,THEORA_TABLES_DATA);
			}
		}else{
			enc_fill_yuv(&s->yuv,im);
			ms_debug("subtmitting yuv frame to theora encoder...");
			if (theora_encode_YUVin(&s->tstate,&s->yuv)!=0){
				ms_error("theora_encode_YUVin error.");
			}else{
				if (theora_encode_packetout(&s->tstate,0,&op)==1){
					ms_debug("Got theora coded frame");
					om=allocb(op.bytes,0);
					memcpy(om->b_wptr,op.packet,op.bytes);
					om->b_wptr+=op.bytes;
					packetize_and_send(f,s,om,timestamp,THEORA_RAW_DATA);
				}
			}
		}
		s->frame_count++;
		freemsg(im);
	}
}

static MSFilterMethod enc_methods[]={
	{	MS_FILTER_SET_VIDEO_SIZE, enc_set_vsize },
	{	MS_FILTER_SET_FPS,	enc_set_fps	},
	{	MS_FILTER_ADD_ATTR, enc_add_attr	},
	{	MS_FILTER_SET_BITRATE, enc_set_br	},
	{	0			, NULL }
};

MSFilterDesc ms_theora_enc_desc={
	.id=MS_THEORA_ENC_ID,
	.name="MSTheoraEnc",
	.text="The theora video encoder from xiph.org",
	.category=MS_FILTER_ENCODER,
	.enc_fmt="x-theora",
	.ninputs=1,
	.noutputs=1,
	.init=enc_init,
	.preprocess=enc_preprocess,
	.process=enc_process,
	.postprocess=enc_postprocess,
	.uninit=enc_uninit,
	.methods=enc_methods
};

MS_FILTER_DESC_EXPORT(ms_theora_enc_desc)

typedef struct DecState{
	theora_state tstate;
	theora_info tinfo;
	mblk_t *yuv;
	mblk_t *curframe;
	bool_t header_recv;
	bool_t tables_recv;
	bool_t ready;
}DecState;

static void dec_init(MSFilter *f){
	DecState *s=ms_new(DecState,1);
	s->ready=FALSE;
	s->header_recv=FALSE;
	s->tables_recv=FALSE;
	theora_info_init(&s->tinfo);
	s->yuv=NULL;
	s->curframe=NULL;
	f->data=s;
}

static void dec_uninit(MSFilter *f){
	DecState *s=(DecState*)f->data;
	if (s->yuv!=NULL) freemsg(s->yuv);
	if (s->curframe!=NULL) freemsg(s->curframe);
	theora_info_clear(&s->tinfo);
	ms_free(s);
}

static bool_t dec_init_theora(DecState *s, ogg_packet *op, int tdt){
	int err;
	theora_comment tcom;
	theora_comment_init(&tcom);
	tcom.vendor="dummy";
	op->b_o_s=1;
	err=theora_decode_header(&s->tinfo,&tcom,op);
	if (err==0){
		switch(tdt){
			case THEORA_HEADER_DATA:
				ms_debug("Theora header decoded");
				s->header_recv=TRUE;
				break;
			case THEORA_COMMENT_DATA:
				ms_debug("Theora comment decoded");
				break;
			case THEORA_TABLES_DATA:
				ms_debug("Theora tables decoded");
				s->tables_recv=TRUE;
				break;
			default:
				ms_error("bad theora payload header");
		}
		if (s->header_recv && s->tables_recv){
			if (theora_decode_init(&s->tstate,&s->tinfo)==0){
				ms_debug("theora decoder ready, pixfmt=%i",
					s->tinfo.pixelformat);
				return TRUE;	
			}
		}
	}else{
		ms_warning("error decoding theora header of type %i",tdt);
	}
	return FALSE;
}
/* remove payload header and agregates fragmented packets */
static mblk_t *dec_unpacketize(MSFilter *f, DecState *s, mblk_t *im, int *tdt){
	mblk_t *ret=NULL;
	*tdt=payload_header_get_tdt((uint8_t*)im->b_rptr);
	im->b_rptr+=4;
	if (s->curframe!=NULL){
		concatb(s->curframe,im);
	}else s->curframe=im;
	if (mblk_get_marker_info(im)) {
		ret=s->curframe;
		msgpullup(ret,-1);
		s->curframe=NULL;
	}
	return ret;
}

static void dec_process_frame(MSFilter *f, DecState *s, ogg_packet *op){
	yuv_buffer yuv;
	if (theora_decode_packetin(&s->tstate,op)==0){
		if (theora_decode_YUVout(&s->tstate,&yuv)==0){
			mblk_t *om;
			int i;
			int ylen=yuv.y_width*yuv.y_height;
			int uvlen=yuv.uv_width*yuv.uv_height;
			ms_debug("Got yuv buffer from theora decoder");
			if (s->yuv==NULL){
				int len=(ylen)+(2*uvlen);
				s->yuv=allocb(len,0);
			}
			om=dupb(s->yuv);
			for(i=0;i<yuv.y_height;++i){
				memcpy(om->b_wptr,yuv.y+yuv.y_stride*i,yuv.y_width);
				om->b_wptr+=yuv.y_width;
			}
			for(i=0;i<yuv.uv_height;++i){
				memcpy(om->b_wptr,yuv.u+yuv.uv_stride*i,yuv.uv_width);
				om->b_wptr+=yuv.uv_width;
			}
			for(i=0;i<yuv.uv_height;++i){
				memcpy(om->b_wptr,yuv.v+yuv.uv_stride*i,yuv.uv_width);
				om->b_wptr+=yuv.uv_width;
			}
			ms_queue_put(f->outputs[0],om);
		}
	}else{
		ms_warning("theora decoding error");
	}
}

static void dec_process(MSFilter *f){
	mblk_t *im;
	mblk_t *m;
	ogg_packet op;
	int tdt;
	DecState *s=(DecState*)f->data;
	while( (im=ms_queue_get(f->inputs[0]))!=0) {
		m=dec_unpacketize(f,s,im,&tdt);
		if (m!=NULL){
			/* now in im we have only the theora data*/
			op.packet=(uint8_t*)m->b_rptr;
			op.bytes=m->b_wptr-m->b_rptr;
			op.b_o_s=0;
			op.e_o_s=0;
			op.granulepos=0;
			op.packetno=0;
			if (tdt!=THEORA_RAW_DATA) /*packed conf*/ {
				if (!s->ready){
					if (dec_init_theora(s,&op,tdt))
						s->ready=TRUE;
				}
			}else{
				if (s->ready){
					dec_process_frame(f,s,&op);
				}else{
					ms_warning("skipping theora packet because decoder was not initialized yet with theora header and tables");
				}
			}
			freemsg(m);
		}
	}
}

MSFilterDesc ms_theora_dec_desc={
	.id=MS_THEORA_DEC_ID,
	.name="MSTheoraDec",
	.text="The theora video decoder from xiph.org",
	.category=MS_FILTER_DECODER,
	.enc_fmt="x-theora",
	.ninputs=1,
	.noutputs=1,
	.init=dec_init,
	.process=dec_process,
	.uninit=dec_uninit
};

MS_FILTER_DESC_EXPORT(ms_theora_dec_desc)
