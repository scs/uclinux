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

typedef struct SizeConvState{
	MSVideoSize target_vsize;
	MSVideoSize input_vsize;
	ImgReSampleContext *rsctx;
	mblk_t *om;
	int in_size;
	int out_size;
} SizeConvState;

static int cif_yuv_size=0;
static int qcif_yuv_size=0;
static int qvga_yuv_size=0;

/*this MSFilter will do on the fly picture size conversion. It attempts to guess the picture size from the yuv buffer size. YUV420P is assumed on input.
For now it only supports QCIF->CIF, QVGA->CIF and CIF->CIF (does nothing in this case)*/

static void size_conv_init(MSFilter *f){
	SizeConvState *s=ms_new(SizeConvState,1);
	s->target_vsize.width = MS_VIDEO_SIZE_CIF_W;
	s->target_vsize.height = MS_VIDEO_SIZE_CIF_H;
	s->input_vsize.width = MS_VIDEO_SIZE_CIF_W;
	s->input_vsize.height = MS_VIDEO_SIZE_CIF_H;
	s->rsctx=NULL;
	s->om=NULL;
	s->in_size=0;
	s->out_size=avpicture_get_size(PIX_FMT_YUV420P,s->target_vsize.width,s->target_vsize.height);
	f->data=s;
	if (cif_yuv_size==0){
		cif_yuv_size=avpicture_get_size(PIX_FMT_YUV420P,MS_VIDEO_SIZE_CIF_W,MS_VIDEO_SIZE_CIF_H);
		qcif_yuv_size=avpicture_get_size(PIX_FMT_YUV420P,MS_VIDEO_SIZE_QCIF_W,MS_VIDEO_SIZE_QCIF_H);
		qvga_yuv_size=avpicture_get_size(PIX_FMT_YUV420P,MS_VIDEO_SIZE_QVGA_W,MS_VIDEO_SIZE_QVGA_H);
	}
}

static void size_conv_uninit(MSFilter *f){
	SizeConvState *s=(SizeConvState*)f->data;
	freemsg(s->om);
	ms_free(s);
}

static void size_conv_postprocess(MSFilter *f){
	SizeConvState *s=(SizeConvState*)f->data;
	if (s->rsctx!=NULL) {
		img_resample_close(s->rsctx);
		s->rsctx=NULL;
	}
}

static mblk_t * size_conv_alloc_mblk(SizeConvState *s){
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
	s->om=allocb(s->out_size,0);
	s->om->b_wptr=s->om->b_datap->db_lim;
	return dupmsg(s->om);
}

static void init_resampler(SizeConvState *s, int size){
	if (s->rsctx!=NULL){
		img_resample_close(s->rsctx);
		s->rsctx=NULL;
	}
	s->in_size=size;
	if (size!=s->out_size){
		if (size==cif_yuv_size){
			s->input_vsize.width=MS_VIDEO_SIZE_CIF_W;
			s->input_vsize.height=MS_VIDEO_SIZE_CIF_H;
		}else if (size==qcif_yuv_size){
			s->input_vsize.width=MS_VIDEO_SIZE_QCIF_W;
			s->input_vsize.height=MS_VIDEO_SIZE_QCIF_H;
		}else if (size==qvga_yuv_size){
			s->input_vsize.width=MS_VIDEO_SIZE_QVGA_W;
			s->input_vsize.height=MS_VIDEO_SIZE_QVGA_H;
		}else{
			ms_error("Unsupported image size !");
			return;
		}
		s->rsctx=img_resample_init(s->target_vsize.width,s->target_vsize.height,s->input_vsize.width,s->input_vsize.height);
	}
}

static void size_conv_process(MSFilter *f){
	SizeConvState *s=(SizeConvState*)f->data;
	mblk_t *im,*om;
	int sz;
	AVPicture orig,dest;
	while((im=ms_queue_get(f->inputs[0]))!=NULL ){
		sz=msgdsize(im);
		if (sz!=s->in_size){
			init_resampler(s,sz);
		}
		if (s->rsctx!=NULL){
			avpicture_fill(&orig,(unsigned char *)im->b_rptr,PIX_FMT_YUV420P,s->input_vsize.width,s->input_vsize.height);
			om=size_conv_alloc_mblk(s);
			avpicture_fill(&dest,(uint8_t*)om->b_rptr,PIX_FMT_YUV420P,s->target_vsize.width,s->target_vsize.height);
			img_resample(s->rsctx,&dest,&orig);
			freemsg(im);
			ms_queue_put(f->outputs[0],om);
		}else{
			ms_queue_put(f->outputs[0],im);
		}
	}
}


static int sizeconv_set_vsize(MSFilter *f, void*arg){
	SizeConvState *s=(SizeConvState*)f->data;
	s->target_vsize=*(MSVideoSize*)arg;

	freemsg(s->om);

	if (s->rsctx!=NULL) {
		img_resample_close(s->rsctx);
		s->rsctx=NULL;
	}

	s->input_vsize.width = MS_VIDEO_SIZE_CIF_W;
	s->input_vsize.height = MS_VIDEO_SIZE_CIF_H;
	s->rsctx=NULL;
	s->in_size=0;
	s->out_size=avpicture_get_size(PIX_FMT_YUV420P,s->target_vsize.width,s->target_vsize.height);
	if (cif_yuv_size==0){
		cif_yuv_size=avpicture_get_size(PIX_FMT_YUV420P,MS_VIDEO_SIZE_CIF_W,MS_VIDEO_SIZE_CIF_H);
		qcif_yuv_size=avpicture_get_size(PIX_FMT_YUV420P,MS_VIDEO_SIZE_QCIF_W,MS_VIDEO_SIZE_QCIF_H);
		qvga_yuv_size=avpicture_get_size(PIX_FMT_YUV420P,MS_VIDEO_SIZE_QVGA_W,MS_VIDEO_SIZE_QVGA_H);
	}


	return 0;
}

#if 0
static int sizeconv_set_pixfmt(MSFilter *f, void *arg){
	SizeConvState *s=(SizeConvState*)f->data;
	PixConvState *s=(PixConvState*)f->data;
	s->in_fmt=ms_pix_fmt_to_ffmpeg(fmt);
	return 0;
}
#endif

static MSFilterMethod methods[]={
	{	MS_FILTER_SET_VIDEO_SIZE, sizeconv_set_vsize	},
#if 0
	{	MS_FILTER_SET_PIX_FMT,	sizeconv_set_pixfmt	},
#endif
	{	0	,	NULL }
};

#ifdef _MSC_VER

MSFilterDesc ms_size_conv_desc={
	MS_SIZE_CONV_ID,
	"MSSizeConv",
	"a small video size converter",
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

