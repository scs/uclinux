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
#include "mediastreamer2/msvideoout.h"

#ifndef WIN32

#include <SDL/SDL.h>
#include <SDL/SDL_video.h>

static bool_t sdl_initialized=FALSE;

static SDL_Surface *sdl_screen=0
;
static SDL_Overlay * sdl_create_window(int w, int h){
	SDL_Overlay *lay;
	sdl_screen = SDL_SetVideoMode(w,h, 0,SDL_SWSURFACE);
	if (sdl_screen == NULL ) {
		ms_warning("Couldn't set video mode: %s\n",
						SDL_GetError());
		return NULL;
	}
	if (sdl_screen->flags & SDL_HWSURFACE) ms_message("SDL surface created in hardware");
	SDL_WM_SetCaption("Linphone Video", NULL);
	ms_message("Using yuv overlay.");
	lay=SDL_CreateYUVOverlay(w,h,SDL_YV12_OVERLAY,sdl_screen);
	if (lay==NULL){
		ms_warning("Couldn't create yuv overlay: %s\n",
						SDL_GetError());
		return NULL;
	}else{
		if (lay->hw_overlay) ms_message("YUV overlay using hardware acceleration.");
	}
	return lay;
}

static bool_t sdl_display_init(MSDisplay *obj, MSFrameBuffer *fbuf){
	SDL_Overlay *lay;
	if (!sdl_initialized){
		/* Initialize the SDL library */
		if( SDL_Init(SDL_INIT_VIDEO) < 0 ) {
			ms_error("Couldn't initialize SDL: %s", SDL_GetError());
			return FALSE;
		}
		/* Clean up on exit */
		atexit(SDL_Quit);
		sdl_initialized=TRUE;
	}
	if (obj->data!=NULL)
		SDL_FreeYUVOverlay((SDL_Overlay*)obj->data);
	lay=sdl_create_window(fbuf->w, fbuf->h);
	if (lay){
		fbuf->y=lay->pixels[0];
		fbuf->u=lay->pixels[2];
		fbuf->v=lay->pixels[1];
		obj->data=lay;
		return TRUE;
	}
	return FALSE;
}

static void sdl_display_lock(MSDisplay *obj){
	SDL_LockYUVOverlay((SDL_Overlay*)obj->data);
}

static void sdl_display_unlock(MSDisplay *obj){
	SDL_Overlay *lay=(SDL_Overlay*)obj->data;
	SDL_UnlockYUVOverlay(lay);
}

static void sdl_display_update(MSDisplay *obj){
	SDL_Rect rect;
	SDL_Overlay *lay=(SDL_Overlay*)obj->data;
	rect.x=0;
	rect.y=0;
	rect.w=lay->w;
	rect.h=lay->h;
	SDL_DisplayYUVOverlay(lay,&rect);
}

static void sdl_display_uninit(MSDisplay *obj){
	SDL_Overlay *lay=(SDL_Overlay*)obj->data;
	if (lay!=NULL)
		SDL_FreeYUVOverlay(lay);
	if (sdl_screen!=NULL){
		SDL_FreeSurface(sdl_screen);
		sdl_screen=NULL;
	}
}

MSDisplayDesc ms_sdl_display_desc={
	.init=sdl_display_init,
	.lock=sdl_display_lock,
	.unlock=sdl_display_unlock,
	.update=sdl_display_update,
	.uninit=sdl_display_uninit
};

#else

#include <Vfw.h>


typedef struct _WinDisplay{
	HWND window;
	HDRAWDIB ddh;
	MSFrameBuffer fb;
	uint8_t *rgb;
	int rgb_len;
}WinDisplay;

static LRESULT CALLBACK window_proc(
    HWND hwnd,        // handle to window
    UINT uMsg,        // message identifier
    WPARAM wParam,    // first message parameter
    LPARAM lParam)    // second message parameter
{
	switch(uMsg){
		case WM_DESTROY:
		break;
		default:
			return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}
	return 0;
}

static HWND create_window(int w, int h)
{
	WNDCLASS wc;
	HINSTANCE hInstance = GetModuleHandle(NULL);
	HWND hwnd;
	RECT rect;
	wc.style = 0 ;
	wc.lpfnWndProc = window_proc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = NULL;
	wc.hIcon = NULL;
	wc.hCursor = LoadCursor(hInstance, IDC_ARROW);
	wc.hbrBackground = NULL;
	wc.lpszMenuName =  NULL;
	wc.lpszClassName = "Video Window";
	
	if(!RegisterClass(&wc))
	{
		/* already registred! */
	}
	rect.left=100;
	rect.top=100;
	rect.right=rect.left+w;
	rect.bottom=rect.top+h;
	if (!AdjustWindowRect(&rect,WS_CAPTION ,FALSE)){
		ms_error("AdjustWindowRect failed.");
	}
	ms_message("AdjustWindowRect: %li,%li %li,%li",rect.left,rect.top,rect.right,rect.bottom);
	hwnd=CreateWindow("Video Window", "Video window", WS_OVERLAPPEDWINDOW|WS_VISIBLE ,
						CW_USEDEFAULT, CW_USEDEFAULT, rect.right-rect.left,rect.bottom-rect.top,
													NULL, NULL, hInstance, NULL);
	if (hwnd==NULL){
		ms_error("Fail to create video window");
	}
	return hwnd;
}

static bool_t win_display_init(MSDisplay *obj, MSFrameBuffer *fbuf){
	WinDisplay *wd=(WinDisplay*)obj->data;
	int ysize,usize;
	if (!wd) {
		wd=ms_new0(WinDisplay,1);
		obj->data=wd;
	}
	
	wd->fb.w=fbuf->w;
	wd->fb.h=fbuf->h;
	
	wd->window=(HWND)obj->window_id;
	if (wd->window==NULL) {
		wd->window=create_window(wd->fb.w,wd->fb.h);
	}
	if (wd->window==NULL) return FALSE;
	if (wd->ddh==NULL) wd->ddh=DrawDibOpen();
	if (wd->ddh==NULL){
		ms_error("DrawDibOpen() failed.");
		return FALSE;
	}
	/*allocate yuv and rgb buffers*/
	if (wd->fb.y) ms_free(wd->fb.y);
	if (wd->rgb) ms_free(wd->rgb);
	ysize=wd->fb.w*wd->fb.h;
	usize=ysize/4;
	fbuf->y=wd->fb.y=ms_malloc0(ysize+2*usize);
	fbuf->u=wd->fb.u=wd->fb.y+ysize;
	fbuf->v=wd->fb.v=wd->fb.u+usize;
	wd->rgb_len=ysize*3;
	wd->rgb=ms_malloc0(wd->rgb_len);
	return TRUE;
}

typedef struct rgb{
	uint8_t r,g,b;
} rgb_t;

typedef struct yuv{
	uint8_t y,u,v;
} yuv_t;


#if 1
static inline uint8_t ms_clip_uint8(int a)
{
     if (a&(~255)) return (-a)>>31;
     else          return a;
}
/* R = Y + 1.140V
   G = Y - 0.395U - 0.581V
   B = Y + 2.032U
   or
	R = Y + 1.403V'
	G = Y - 0.344U' - 0.714V'
	B = Y + 1.770U'
*/
static void yuv_to_rgb_pixel(const yuv_t *yuv, rgb_t *rgb){
	int c,d,e;
	c=yuv->y-16;
	e=yuv->u-128;
	d=yuv->v-128;
	rgb->r=ms_clip_uint8((float)c + 1.403*e);
	rgb->g=ms_clip_uint8((float)c - 0.344*d - 0.714*e );
	rgb->b=ms_clip_uint8((float)c + 1.77*d );
}

static void yuv420p_to_rgb(uint8_t *yuv, uint8_t *rgb, int w, int h){
	int i,j,k,l;
	yuv_t yuv_pix;
	uint8_t *y,*u,*v;
	int upos;
	int ypos;
	y=yuv;
	u=yuv + w*h;
	v=u + (w*h/4);
	for(i=h-1,k=(h/2)-1;i>=0;i-=2,--k){
		ypos=i*w;
		upos=k*w/2;
		for(j=0,l=0;j<w;j+=2,++l){
			yuv_pix.y=y[ypos+j];
			yuv_pix.u=u[upos+l];
			yuv_pix.v=v[upos+l];
			yuv_to_rgb_pixel(&yuv_pix,(rgb_t*)rgb);
			rgb+=3;
			yuv_pix.y=y[ypos+j+1];
			yuv_to_rgb_pixel(&yuv_pix,(rgb_t*)rgb);
			rgb+=3;
		}
		ypos=(i-1)*w;
		for(j=0,l=0;j<w;j+=2,++l){
			yuv_pix.y=y[ypos+j];
			yuv_pix.u=u[upos+l];
			yuv_pix.v=v[upos+l];
			yuv_to_rgb_pixel(&yuv_pix,(rgb_t*)rgb);
			rgb+=3;
			yuv_pix.y=y[ypos+j+1];
			yuv_to_rgb_pixel(&yuv_pix,(rgb_t*)rgb);
			rgb+=3;
		}
	}
}
#else
#include <ffmpeg/avcodec.h>
static void yuv420p_to_rgb(uint8_t *yuv, uint8_t *rgb, int w, int h){
	AVPicture src,dst;
	avpicture_fill(&dst,rgb,PIX_FMT_RGB24,w,h);
	avpicture_fill(&src,yuv,PIX_FMT_YUV420P,w,h);
	if (img_convert(&dst,PIX_FMT_RGB24,&src,PIX_FMT_YUV420P,w,h)<0){
		ms_error("videout.c: img_convert failed !");
	}
}
#endif

static void win_display_update(MSDisplay *obj){
	WinDisplay *wd=(WinDisplay*)obj->data;
	HDC hdc;
	BITMAPINFOHEADER bi;
	bool_t ret;
	if (wd->window==NULL) return;
	hdc=GetDC(wd->window);
	if (hdc==NULL) {
		ms_error("Could not get window dc");
		return;
	}
	yuv420p_to_rgb(wd->fb.y, wd->rgb, wd->fb.w, wd->fb.h);
	memset(&bi,0,sizeof(bi));
	bi.biSize=sizeof(bi);
	/*
	bi.biWidth=wd->fb.w;
	bi.biHeight=wd->fb.h;
	bi.biPlanes=3;
	bi.biBitCount=12;
	bi.biCompression=MAKEFOURCC('I','4','2','0');
	bi.biSizeImage=(wd->fb.w*wd->fb.h*3)/2;
	*/
	bi.biWidth=wd->fb.w;
	bi.biHeight=wd->fb.h;
	bi.biPlanes=1;
	bi.biBitCount=24;
	bi.biCompression=BI_RGB;
	bi.biSizeImage=wd->rgb_len;
	ret=DrawDibDraw(wd->ddh,hdc,0,0,wd->fb.w,wd->fb.h,&bi,wd->rgb,
		0,0,wd->fb.w,wd->fb.h,0);
  	if (!ret) ms_error("DrawDibDraw failed.");
	ReleaseDC(NULL,hdc);
}

static void win_display_uninit(MSDisplay *obj){
	WinDisplay *wd=(WinDisplay*)obj->data;
	if (wd->window && !obj->window_id) DestroyWindow(wd->window);
	if (wd->ddh) DrawDibClose(wd->ddh);
	if (wd->fb.y) ms_free(wd->fb.y);
	if (wd->rgb) ms_free(wd->rgb);
	ms_free(wd);
}

#ifdef _MSC_VER

MSDisplayDesc ms_win_display_desc={
	win_display_init,
	NULL,
	NULL,
	win_display_update,
	win_display_uninit
};

#else

MSDisplayDesc ms_win_display_desc={
	.init=win_display_init,
	.update=win_display_update,
	.uninit=win_display_uninit
};

#endif

#endif

MSDisplay *ms_display_new(MSDisplayDesc *desc){
	MSDisplay *obj=ms_new0(MSDisplay,1);
	obj->desc=desc;
	obj->data=NULL;
	return obj;
}

void ms_display_set_window_id(MSDisplay *d, long id){
	d->window_id=id;
}

void ms_display_destroy(MSDisplay *obj){
	obj->desc->uninit(obj);
	ms_free(obj);
}

typedef struct VideoOut
{
	MSVideoSize size;
	MSVideoSize local_size; /*size of local preview */
	MSFrameBuffer fbuf;
	mblk_t *smallb;
	int scale_factor;
	MSDisplay *display;
	bool_t lsize_init;
	bool_t own_display;
} VideoOut;


#define SCALE_FACTOR 6

static void video_out_init(MSFilter  *f){
	VideoOut *obj=ms_new(VideoOut,1);
	//obj->size.width = MS_VIDEO_SIZE_CIF_W;
	//obj->size.height = MS_VIDEO_SIZE_CIF_H;
	//obj->local_size.width = MS_VIDEO_SIZE_CIF_W;
	//obj->local_size.height = MS_VIDEO_SIZE_CIF_H;
	obj->size.width = MS_VIDEO_SIZE_QVGA_W;
	obj->size.height = MS_VIDEO_SIZE_QVGA_H;
	obj->local_size.width = MS_VIDEO_SIZE_QVGA_W;
	obj->local_size.height = MS_VIDEO_SIZE_QVGA_H;
	obj->lsize_init=FALSE;
	obj->scale_factor=SCALE_FACTOR;
	obj->smallb=NULL;
	obj->display=NULL;
	obj->own_display=FALSE;
	f->data=obj;
}


static void video_out_uninit(MSFilter *f){
	VideoOut *s=(VideoOut*)f->data;
	if (s->smallb!=NULL) freemsg(s->smallb);
	if (s->display!=NULL && s->own_display) ms_display_destroy(s->display);
	ms_free(s);
}

static mblk_t * resize_yuv_small(unsigned char *pict, int w, int h, int scale){
	int i,j,id,jd;
	int nh,nw;
	unsigned char *smallpict;
	int ysize,usize,ydsize,udsize;
	int smallpict_sz;
	unsigned char *dptr,*sptr;
	mblk_t *smallb;
	nw=w/scale;
	nh=h/scale;
	ysize=w*h;
	usize=ysize/4;
	ydsize=nw*nh;
	udsize=ydsize/4;
	smallpict_sz=(ydsize*3)/2;
	smallb=allocb(smallpict_sz,0);
	smallpict=smallb->b_wptr;
	smallb->b_wptr+=smallpict_sz;
	
	dptr=smallpict;
	sptr=pict;
	for (j=0,jd=0;j<nh;j++,jd+=scale){
		for (i=0,id=0;i<nw;i++,id+=scale){
			dptr[(j*nw) + i]=sptr[(jd*w)+id];
		}
	}
	
	nh=nh/2;
	nw=nw/2;
	w=w/2;
	h=h/2;
	dptr+=ydsize;
	sptr+=ysize;
	for (j=0,jd=0;j<nh;j++,jd+=scale){
		for (i=0,id=0;i<nw;i++,id+=scale){
			dptr[(j*nw) + i]=sptr[(jd*w)+id];
		}
	}
	dptr+=udsize;
	sptr+=usize;
	for (j=0,jd=0;j<nh;j++,jd+=scale){
		for (i=0,id=0;i<nw;i++,id+=scale){
			dptr[(j*nw) + i]=sptr[(jd*w)+id];
		}
	}
	
	return smallb;
}

static void fill_overlay_at_pos(VideoOut *obj, mblk_t *m, int x, int y, int w, int h){
	MSFrameBuffer *lay=&obj->fbuf;
	unsigned char *data=m->b_rptr;
	int i,j;
	int jlim,ilim;
	int off;
	unsigned char *dptr;
	
	ilim=MIN(x+w,lay->w);
	jlim=MIN(y+h,lay->h);
	ms_display_lock(obj->display);
	/* set Y */
	dptr=lay->y;
	for (j=y;j<jlim;j++){
		off=j*lay->w;
		for (i=x;i<ilim;i++){
			dptr[off + i]=*data;
			data++;
		}
	}
	/*set U and V*/
	ilim=ilim/2;
	jlim=jlim/2;
	dptr=lay->u;
	for (j=y/2;j<jlim;j++){
		off=j*(lay->w/2);
		for (i=x/2;i<ilim;i++){
			dptr[off + i]=*data;
			data++;
		}
	}
	dptr=lay->v;
	for (j=y/2;j<jlim;j++){
		off=j*(lay->w/2);
		for (i=x/2;i<ilim;i++){
			dptr[off + i]=*data;
			data++;
		}
	}
	ms_display_unlock(obj->display);
}

static void fill_overlay(VideoOut *obj ,mblk_t *m){
	MSFrameBuffer *lay=&obj->fbuf;
	int w2,h2;
	char *data=(char*)m->b_rptr;
	int ysize=lay->w*lay->h;
	int usize;
	w2=lay->w/2;
	h2=lay->h/2;
	usize=w2*h2;
	ms_display_lock(obj->display);
	memcpy(lay->y,data,ysize);
	memcpy(lay->u,data+ysize,usize);
	memcpy(lay->v,data+ysize+usize,usize);
	ms_display_unlock(obj->display);
}


static void video_out_preprocess(MSFilter *f){
	VideoOut *obj=(VideoOut*)f->data;
	obj->fbuf.w=obj->size.width;
	obj->fbuf.h=obj->size.height;
	if (obj->display==NULL){
#ifndef WIN32
		obj->display=ms_display_new(&ms_sdl_display_desc);
#else
		obj->display=ms_display_new(&ms_win_display_desc);
#endif
		obj->own_display=TRUE;
	}
	if (!ms_display_init(obj->display,&obj->fbuf)){
		if (obj->own_display) ms_display_destroy(obj->display);
		obj->display=NULL;
	}
}

static void video_out_postprocess(MSFilter *f){
}

static void video_out_process(MSFilter *f){
	VideoOut *obj=(VideoOut*)f->data;
	mblk_t *inm0=NULL;
	mblk_t *inm1=NULL;
	MSRect smallrect, rect;
	bool_t got_preview=FALSE;

	rect.w=obj->size.width;
	rect.h=obj->size.height;
	rect.x=0;
	rect.y=0;
	smallrect.w=obj->size.width/SCALE_FACTOR;
	smallrect.h=obj->size.height/SCALE_FACTOR;
	smallrect.x=obj->size.width - smallrect.w ;
	smallrect.y=obj->size.height -smallrect.h;
	
	if (obj->display==NULL){
		ms_queue_flush(f->inputs[0]);
		ms_queue_flush(f->inputs[1]);
		return;
	}
	
	while (f->inputs[0]!=NULL && (inm0=ms_queue_get(f->inputs[0]))!=NULL){
		fill_overlay(obj,inm0);
		freemsg(inm0);
	}
	while (f->inputs[1]!=NULL && (inm1=ms_queue_get(f->inputs[1]))!=NULL){
		/* this message is blitted on the right,bottom corner of the screen */
		got_preview=TRUE;
		if (!obj->lsize_init){
			/*attempt to guess the video size of the local preview buffer*/
			int bsize=msgdsize(inm1);
			if (bsize<(MS_VIDEO_SIZE_CIF_W*MS_VIDEO_SIZE_CIF_H*3/2)){
				/*surely qcif ?*/
				obj->local_size.width=MS_VIDEO_SIZE_QCIF_W;
				obj->local_size.height=MS_VIDEO_SIZE_QCIF_H;
				ms_message("preview is in QCIF.");
				obj->scale_factor=SCALE_FACTOR/2;
			}
			obj->lsize_init=TRUE;
		}
		if (obj->smallb!=NULL) {
			freemsg(obj->smallb);
		}
		obj->smallb=resize_yuv_small(inm1->b_rptr,obj->local_size.width,obj->local_size.height,obj->scale_factor);
		fill_overlay_at_pos(obj,obj->smallb,smallrect.x, smallrect.y, smallrect.w, smallrect.h);
		freemsg(inm1);
	}
	if (!got_preview){
		/* this is the case were we have only inm0, we have to redisplay inm1 */
		if (obj->smallb!=NULL){
			fill_overlay_at_pos(obj,obj->smallb,smallrect.x, smallrect.y, smallrect.w, smallrect.h);
		}
	}
	ms_display_update(obj->display);
}

static int video_out_set_vsize(MSFilter *f,void *arg){
	VideoOut *s=(VideoOut*)f->data;
	s->size=*(MSVideoSize*)arg;
	s->local_size=*(MSVideoSize*)arg;
	return 0;
}

static int video_out_set_display(MSFilter *f,void *arg){
	VideoOut *s=(VideoOut*)f->data;
	s->display=(MSDisplay*)arg;
	return 0;
}

static MSFilterMethod methods[]={
	{	MS_FILTER_SET_VIDEO_SIZE	,	video_out_set_vsize },
	{	MS_VIDEO_OUT_SET_DISPLAY	,	video_out_set_display},
	{	0	,NULL}
};

#ifdef _MSC_VER

MSFilterDesc ms_video_out_desc={
	MS_VIDEO_OUT_ID,
	"MSVideoOut",
	"A generic video display",
	MS_FILTER_OTHER,
	NULL,
	2,
	0,
	video_out_init,
	video_out_preprocess,
	video_out_process,
	video_out_postprocess,
	video_out_uninit,
	methods
};

#else

MSFilterDesc ms_video_out_desc={
	.id=MS_VIDEO_OUT_ID,
	.name="MSVideoOut",
	.text="A generic video display",
	.category=MS_FILTER_OTHER,
	.ninputs=2,
	.noutputs=0,
	.init=video_out_init,
	.preprocess=video_out_preprocess,
	.process=video_out_process,
	.postprocess=video_out_postprocess,
	.uninit=video_out_uninit,
	.methods=methods
};

#endif

MS_FILTER_DESC_EXPORT(ms_video_out_desc)
