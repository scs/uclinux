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
#include "mediastreamer2/msvideo.h"

#include <ffmpeg/avcodec.h>
#include <ffmpeg/swscale.h>

typedef struct SizeConvState{
	MSVideoSize target_vsize;
	MSVideoSize in_vsize;
	YuvBuf outbuf;
	struct SwsContext *sws_ctx;
	mblk_t *om;
} SizeConvState;


/*this MSFilter will do on the fly picture size conversion. It attempts to guess the picture size from the yuv buffer size. YUV420P is assumed on input.
For now it only supports QCIF->CIF, QVGA->CIF and CIF->CIF (does nothing in this case)*/

static void size_conv_init(MSFilter *f){
	SizeConvState *s=(SizeConvState *)ms_new(SizeConvState,1);
	s->target_vsize.width = MS_VIDEO_SIZE_CIF_W;
	s->target_vsize.height = MS_VIDEO_SIZE_CIF_H;
	s->in_vsize.width=0;
	s->in_vsize.height=0;
	s->sws_ctx=NULL;
	s->om=NULL;
	f->data=s;
}

static void size_conv_uninit(MSFilter *f){
	SizeConvState *s=(SizeConvState*)f->data;
	ms_free(s);
}

static void size_conv_postprocess(MSFilter *f){
	SizeConvState *s=(SizeConvState*)f->data;
	if (s->sws_ctx!=NULL) {
		sws_freeContext(s->sws_ctx);
		s->sws_ctx=NULL;
	}
	if (s->om!=NULL){
		freemsg(s->om);
		s->om=NULL;
	}
}

static mblk_t *size_conv_alloc_mblk(SizeConvState *s){
	if (s->om!=NULL){
		int ref=s->om->b_datap->db_ref;
		if (ref==1){
			return dupmsg(s->om);
		}else{
			/*the last msg is still referenced by somebody else*/
			ms_message("size_conv_alloc_mblk: Somebody still retaining yuv buffer (ref=%i)",ref);
			freemsg(s->om);
			s->om=NULL;
		}
	}
	s->om=yuv_buf_alloc(&s->outbuf,s->target_vsize.width,s->target_vsize.height);
	return dupmsg(s->om);
}

static struct SwsContext * get_resampler(SizeConvState *s, int w, int h){
	if (s->in_vsize.width!=w ||
		s->in_vsize.height!=h || s->sws_ctx==NULL){
		if (s->sws_ctx!=NULL){
			sws_freeContext(s->sws_ctx);
			s->sws_ctx=NULL;
		}
		s->sws_ctx=sws_getContext(w,h,PIX_FMT_YUV420P,
			s->target_vsize.width,s->target_vsize.height,PIX_FMT_YUV420P,
			SWS_FAST_BILINEAR,NULL, NULL, NULL);
		s->in_vsize.width=w;
		s->in_vsize.height=h;
	}
	return s->sws_ctx;
}

static void size_conv_process(MSFilter *f){
	SizeConvState *s=(SizeConvState*)f->data;
	YuvBuf inbuf;
	mblk_t *im;
	ms_filter_lock(f);
	while((im=ms_queue_get(f->inputs[0]))!=NULL ){
		if (yuv_buf_init_from_mblk(&inbuf,im)==0){
			if (inbuf.w==s->target_vsize.width &&
				inbuf.h==s->target_vsize.height){
				ms_queue_put(f->outputs[0],im);
			}else{
				struct SwsContext *sws_ctx=get_resampler(s,inbuf.w,inbuf.h);
				mblk_t *om=size_conv_alloc_mblk(s);
				if (sws_scale(sws_ctx,inbuf.planes,inbuf.strides, 0,
					0, s->outbuf.planes, s->outbuf.strides)!=0){
					ms_error("MSSizeConv: error in sws_scale().");
				}
				ms_queue_put(f->outputs[0],om);
				freemsg(im);
			}
		}else freemsg(im);
	}
	ms_filter_unlock(f);
}


static int sizeconv_set_vsize(MSFilter *f, void*arg){
	SizeConvState *s=(SizeConvState*)f->data;
	ms_filter_lock(f);
	s->target_vsize=*(MSVideoSize*)arg;
	freemsg(s->om);
	s->om=NULL;
	if (s->sws_ctx!=NULL) {
		sws_freeContext(s->sws_ctx);
		s->sws_ctx=NULL;
	}
	ms_filter_unlock(f);
	return 0;
}



static MSFilterMethod methods[]={
	{	MS_FILTER_SET_VIDEO_SIZE, sizeconv_set_vsize	},
	{	0	,	NULL }
};

#ifdef _MSC_VER

MSFilterDesc ms_size_conv_desc={
	MS_SIZE_CONV_ID,
	"MSSizeConv",
	"A video size converter",
	MS_FILTER_OTHER,
	NULL,
	1,
	1,
	size_conv_init,
	NULL,
	size_conv_process,
	size_conv_postprocess,
	size_conv_uninit,
	methods
};

#else

MSFilterDesc ms_size_conv_desc={
	.id=MS_SIZE_CONV_ID,
	.name="MSSizeConv",
	.text="a small video size converter",
	.ninputs=1,
	.noutputs=1,
	.init=size_conv_init,
	.process=size_conv_process,
	.postprocess=size_conv_postprocess,
	.uninit=size_conv_uninit,
	.methods=methods
};

#endif

MS_FILTER_DESC_EXPORT(ms_size_conv_desc)

