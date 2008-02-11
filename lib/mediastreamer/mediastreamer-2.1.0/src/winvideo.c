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

#include "mediastreamer2/msvideo.h"
#include "mediastreamer2/msticker.h"
#include "mediastreamer2/msv4l.h"
#include "Vfw.h"
#include <winuser.h>
#include <Windows.h>

#include "nowebcam.h" /* -> problem with windows compiler */

#ifndef _MSC_VER
#include "vfw-missing.h"
#endif

typedef struct V4wState{
	ms_thread_t thread;
	char dev[512];
	int devidx;
	HWND hwnd;
	HWND capvideo;
	MSVideoSize vsize;
	int pix_fmt;
	mblk_t *mire;
	queue_t rq;
	ms_mutex_t mutex;
	int frame_ind;
	int frame_max;
	float fps;
	float start_time;
	int frame_count;
	bool_t running;
}V4wState;

static void dummy(void*p){
}

LRESULT CALLBACK VideoStreamCallback(HWND hWnd, LPVIDEOHDR lpVHdr)
{
	V4wState *s;
	mblk_t *buf;
	int size;
	
	s = (V4wState *)capGetUserData(hWnd);
	size = lpVHdr->dwBufferLength;
	if (size>0 && s->running){
		buf = esballoc(lpVHdr->lpData,size,0,dummy);
		buf->b_wptr+=size;  
		
		ms_mutex_lock(&s->mutex);
		putq(&s->rq, buf);
		ms_mutex_unlock(&s->mutex);
	}
	return TRUE ;
}

static bool_t try_format(V4wState *s, BITMAPINFO *videoformat, MSPixFmt pixfmt){
	switch(pixfmt){
		case MS_YUV420P:
			videoformat->bmiHeader.biBitCount = 12;
			videoformat->bmiHeader.biCompression=MAKEFOURCC('I','4','2','0');
		break;
		case MS_RGB24:
			videoformat->bmiHeader.biBitCount = 24;
			videoformat->bmiHeader.biCompression=BI_RGB;
		break;
		default:
			return FALSE;
	}
	return capSetVideoFormat(s->capvideo, videoformat, sizeof(BITMAPINFO));
}

static int v4w_open_videodevice(V4wState *s)
{
	CAPTUREPARMS capparam ;
	BITMAPINFO videoformat;
	char compname[5];
	int i;
	char dev[80];
	char ver[80];
	compname[4]='\0';

	for (i = 0; i < 9; i++){
		if (capGetDriverDescription(i, dev, sizeof (dev),
			ver, sizeof (ver)))
		{
			snprintf(s->dev, sizeof(s->dev), "%s/%s",dev,ver);
			ms_message("v4w: detected %s",s->dev);
			s->devidx=i;
			break;
		}
	}
	s->capvideo = capCreateCaptureWindow("Capture Window",WS_OVERLAPPED
		,0,0,s->vsize.width,s->vsize.height,HWND_MESSAGE, 0) ;
	if (s->capvideo==NULL)
	{
		ms_warning("v4w: could not create capture windows");
		return -1;
	}
	if(!capDriverConnect(s->capvideo,s->devidx ))
	{
		ms_warning("v4w: could not connect to capture driver");
		DestroyWindow(s->capvideo);
		s->capvideo=NULL;
		return -1;
	}
	/*
	capPreviewRate(s->capvideo,s->fps) ;
	if(!capPreview (s->capvideo, 1))
	{
		ms_warning("v4w: cannot start video preview");
		capDriverDisconnect(s->capvideo);
		DestroyWindow(s->capvideo);
		s->capvideo=NULL;
		return -1;
	}
	*/
	capCaptureGetSetup(s->capvideo,&capparam,sizeof(capparam)) ;
	capparam.dwRequestMicroSecPerFrame = 100000 ;
	// detach capture from application
	capparam.fYield                    = TRUE ;
	capparam.fMakeUserHitOKToCapture   = FALSE;
	capparam.fAbortLeftMouse           = FALSE;
	capparam.fAbortRightMouse          = FALSE;
	capparam.wPercentDropForError      = 90 ;
	capparam.fCaptureAudio             = FALSE ;
	capparam.fAbortRightMouse	= FALSE;
	capparam.fAbortLeftMouse	= FALSE;
	capparam.AVStreamMaster            = AVSTREAMMASTER_NONE ;

	if (!capCaptureSetSetup(s->capvideo,&capparam,sizeof(capparam))){
		ms_error("capCaptureSetSetup failed.");
	}
	capSetUserData(s->capvideo, s);
	capGetVideoFormat(s->capvideo, &videoformat, sizeof(BITMAPINFO));

	videoformat.bmiHeader.biSizeImage = 0;
	videoformat.bmiHeader.biWidth  = s->vsize.width;
	videoformat.bmiHeader.biHeight = s->vsize.height;
	/* "orig planes = " disp->videoformat.bmiHeader.biPlanes */
	/* "orig bitcount = " disp->videoformat.bmiHeader.biBitCount */
	/* "orig compression = " disp->videoformat.bmiHeader.biCompression */
	memcpy(compname,&videoformat.bmiHeader.biCompression,4);
	ms_message("v4w: camera's current format is %s", compname);

	if (try_format(s,&videoformat,MS_YUV420P)){
		s->pix_fmt=MS_YUV420P;
		ms_message("Using YUV420P");
	}else if (try_format(s,&videoformat,MS_RGB24)){
		s->pix_fmt=MS_RGB24;
		ms_message("Using RGB24");
	}else{
		ms_error("v4w: Failed to set any video format.");
		capDriverDisconnect (s->capvideo);
		DestroyWindow(s->capvideo);
		s->capvideo=NULL;
	}
	capSetCallbackOnVideoStream(s->capvideo, VideoStreamCallback);
	if (!capCaptureSequenceNoFile(s->capvideo)){
		ms_error("v4w: fail to start capture");
		capDriverDisconnect (s->capvideo);
		capSetCallbackOnVideoStream(s->capvideo, NULL);
		DestroyWindow(s->capvideo);
		s->capvideo=NULL;
	}
	return 0;
}

static void v4w_init(MSFilter *f){
	V4wState *s=ms_new0(V4wState,1);

	s->vsize.width=MS_VIDEO_SIZE_CIF_W;
	s->vsize.height=MS_VIDEO_SIZE_CIF_H;
	s->pix_fmt=MS_RGB24;

	s->hwnd = NULL;
	s->capvideo=NULL;
	qinit(&s->rq);
	s->mire=NULL;
	ms_mutex_init(&s->mutex,NULL);
	s->start_time=0;
	s->frame_count=-1;
	s->fps=15;
	f->data=s;
}

static int v4w_start(MSFilter *f, void *arg)
{
	V4wState *s=(V4wState*)f->data;
	s->frame_count=-1;
	return v4w_open_videodevice(s);
}

static int v4w_stop(MSFilter *f, void *arg){
	V4wState *s=(V4wState*)f->data;
	s->frame_count=-1;
	if (s->capvideo){
		capCaptureStop(s->capvideo);
		capDriverDisconnect(s->capvideo);
		DestroyWindow(s->capvideo);
		s->capvideo=NULL;
	}
	return 0;
}

static void v4w_uninit(MSFilter *f){
	V4wState *s=(V4wState*)f->data;
	flushq(&s->rq,0);
	ms_mutex_destroy(&s->mutex);
	freemsg(s->mire);
	ms_free(s);
}

static mblk_t * v4w_make_nowebcam(V4wState *s){
	unsigned char *data;
	unsigned char *p;
	int i,j,pos,linepos;
	int starti,startj;
	if (s->mire==NULL){
		s->mire=allocb(s->vsize.width*s->vsize.height*3,0);
		s->mire->b_wptr=s->mire->b_datap->db_lim;
		memset(s->mire->b_rptr,0,s->mire->b_wptr-s->mire->b_rptr);
		data=s->mire->b_rptr;
		p=data;
		pos=0;
		starti=(s->vsize.width/2)-(gimp_image.width/2);
		startj=(s->vsize.height/2)-(gimp_image.height/2);
		linepos=startj*s->vsize.width*3;
		for (j=startj;j<startj+gimp_image.height;++j){
			p=&data[linepos]+(starti*3);
			for(i=starti;i<starti+gimp_image.width;++i){
				p[0]=gimp_image.pixel_data[pos];
				p[1]=gimp_image.pixel_data[pos+1];
				p[2]=gimp_image.pixel_data[pos+2];
				p+=3;
				pos+=3;
			}
			linepos+=s->vsize.width*3;
		}
	}
	s->frame_ind++;
	return s->mire;
}

static void v4w_preprocess(MSFilter * obj){
	V4wState *s=(V4wState*)obj->data;
	s->running=TRUE;
}

static void v4w_postprocess(MSFilter * obj){
	V4wState *s=(V4wState*)obj->data;
	s->running=FALSE;
}

static void v4w_process(MSFilter * obj){
	V4wState *s=(V4wState*)obj->data;
	mblk_t *m;
	uint32_t timestamp;
	int cur_frame;

	if (s->frame_count==-1){
		s->start_time=obj->ticker->time;
		s->frame_count=0;
	}
	cur_frame=((obj->ticker->time-s->start_time)*s->fps/1000.0);
	if (cur_frame>s->frame_count){
		mblk_t *om=NULL;
		ms_mutex_lock(&s->mutex);
		/*keep the most recent frame if several frames have been captured */
		if (s->capvideo!=NULL){
			while((m=getq(&s->rq))!=NULL){
				if (om!=NULL) freemsg(om);
				om=m;
			}
		}else {
			om=dupmsg(v4w_make_nowebcam(s));
		}
		ms_mutex_unlock(&s->mutex);
		if (om!=NULL){
			timestamp=obj->ticker->time*90;/* rtp uses a 90000 Hz clockrate for video*/
			mblk_set_timestamp_info(om,timestamp);
			ms_queue_put(obj->outputs[0],om);
			/*ms_message("picture sent");*/
		}
		s->frame_count++;
	}
}

static int v4w_set_fps(MSFilter *f, void *arg){
	V4wState *s=(V4wState*)f->data;
	s->fps=*((float*)arg);
	return 0;
}

static int v4w_get_pix_fmt(MSFilter *f,void *arg){
	V4wState *s=(V4wState*)f->data;
	*((MSPixFmt*)arg) = s->pix_fmt;
	return 0;
}

static int v4w_set_vsize(MSFilter *f, void *arg){
	V4wState *s=(V4wState*)f->data;
	s->vsize=*((MSVideoSize*)arg);
	return 0;
}

static int v4w_get_vsize(MSFilter *f, void *arg){
	V4wState *s=(V4wState*)f->data;
	MSVideoSize *vs=(MSVideoSize*)arg;
	vs->width=s->vsize.width;
	vs->height=s->vsize.height;
	return 0;
}

static MSFilterMethod methods[]={
	{	MS_FILTER_SET_FPS	,	v4w_set_fps	},
	{	MS_FILTER_GET_PIX_FMT	,	v4w_get_pix_fmt	},
	{	MS_FILTER_SET_VIDEO_SIZE, v4w_set_vsize	},
	{	MS_FILTER_GET_VIDEO_SIZE, v4w_get_vsize	},
	{	MS_V4L_START			,	v4w_start		},
	{	MS_V4L_STOP			,	v4w_stop		},
	{	0								,	NULL			}
};

#ifdef _MSC_VER

MSFilterDesc ms_v4w_desc={
	MS_V4L_ID,
	"MSV4w",
	"A video4windows compatible source filter to stream pictures.",
	MS_FILTER_OTHER,
	NULL,
	0,
	1,
	v4w_init,
	v4w_preprocess,
	v4w_process,
	v4w_postprocess,
	v4w_uninit,
	methods
};

#else

MSFilterDesc ms_v4w_desc={
	.id=MS_V4L_ID,
	.name="MSV4w",
	.text="A video4windows compatible source filter to stream pictures.",
	.ninputs=0,
	.noutputs=1,
	.category=MS_FILTER_OTHER,
	.init=v4w_init,
	.preprocess=v4w_preprocess,
	.process=v4w_process,
	.postprocess=v4w_postprocess,
	.uninit=v4w_uninit,
	.methods=methods
};

#endif

MS_FILTER_DESC_EXPORT(ms_v4w_desc)
