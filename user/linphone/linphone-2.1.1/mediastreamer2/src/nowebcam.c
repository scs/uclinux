#include "mediastreamer2/mscommon.h"
#include "mediastreamer2/msvideo.h"

#include <ffmpeg/avcodec.h>
#include <ffmpeg/swscale.h>


#ifdef HAVE_CONFIG_H
#include "mediastreamer-config.h"
#endif

#include <sys/stat.h>

#ifdef WIN32
#include <fcntl.h>
#include <sys/types.h>
#include <io.h>
#include <stdio.h>
#include <malloc.h>
#endif

static mblk_t *jpeg2yuv(uint8_t *jpgbuf, int bufsize, MSVideoSize *reqsize){
	AVCodecContext av_context;
	int got_picture=0;
	AVFrame orig;
	AVPicture dest;
	mblk_t *ret;
	struct SwsContext *sws_ctx;

	avcodec_get_context_defaults(&av_context);
	if (avcodec_open(&av_context,avcodec_find_decoder(CODEC_ID_MJPEG))<0){
		ms_error("jpeg2yuv: avcodec_open failed");
		return NULL;
	}
	if (avcodec_decode_video(&av_context,&orig,&got_picture,jpgbuf,bufsize)<0){
		ms_error("jpeg2yuv: avcodec_decode_video failed");
		avcodec_close(&av_context);
		return NULL;
	}
	ret=allocb(avpicture_get_size(PIX_FMT_YUV420P,reqsize->width,reqsize->height),0);
	ret->b_wptr=ret->b_datap->db_lim;
	avpicture_fill(&dest,ret->b_rptr,PIX_FMT_YUV420P,reqsize->width,reqsize->height);
	
	sws_ctx=sws_getContext(av_context.width,av_context.height,PIX_FMT_YUV420P,
		reqsize->width,reqsize->height,PIX_FMT_YUV420P,SWS_FAST_BILINEAR,
                NULL, NULL, NULL);
	sws_scale(sws_ctx,orig.data,orig.linesize,0,0,dest.data,dest.linesize);
	sws_freeContext(sws_ctx);
	avcodec_close(&av_context);
	return ret;
}

mblk_t *ms_load_jpeg_as_yuv(const char *jpgpath, MSVideoSize *reqsize){
	mblk_t *m=NULL;
	struct stat statbuf;
	uint8_t *jpgbuf;
#if !defined(_MSC_VER)
	int fd=open(jpgpath,O_RDONLY);
#else
	int fd=_open(jpgpath,O_RDONLY);
#endif
	if (fd!=-1){
		fstat(fd,&statbuf);
		jpgbuf=(uint8_t*)alloca(statbuf.st_size);
#if !defined(_MSC_VER)
		read(fd,jpgbuf,statbuf.st_size);
#else
		_read(fd,jpgbuf,statbuf.st_size);
#endif
		m=jpeg2yuv(jpgbuf,statbuf.st_size,reqsize);
	}else{
		ms_error("Cannot load %s",jpgpath);
	}
	return m;
}

#ifndef PACKAGE_DATA_DIR
#define PACKAGE_DATA_DIR "."
#endif

#define NOWEBCAM_JPG "nowebcamCIF"

mblk_t *ms_load_nowebcam(MSVideoSize *reqsize, int idx){
	char tmp[256];
	if (idx<0)
		snprintf(tmp, sizeof(tmp), "%s/images/%s.jpg", PACKAGE_DATA_DIR, NOWEBCAM_JPG);
	else
		snprintf(tmp, sizeof(tmp), "%s/images/%s%i.jpg", PACKAGE_DATA_DIR, NOWEBCAM_JPG, idx);
	return ms_load_jpeg_as_yuv(tmp,reqsize);
}
