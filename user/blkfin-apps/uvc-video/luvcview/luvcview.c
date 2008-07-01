/*******************************************************************************
#	 	luvcview: Sdl video Usb Video Class grabber           .        #
#This package work with the Logitech UVC based webcams with the mjpeg feature. #
#All the decoding is in user space with the embedded jpeg decoder              #
#.                                                                             #
# 		Copyright (C) 2005 2006 Laurent Pinchart &&  Michel Xhaard     #
#                                                                              #
# This program is free software; you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation; either version 2 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program; if not, write to the Free Software                  #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA    #
#                                                                              #
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <string.h>
#include <pthread.h>
#include <SDL/SDL.h>
#include <SDL/SDL_thread.h>
#include <SDL/SDL_audio.h>
#include <SDL/SDL_timer.h>
#include <linux/videodev.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <SDL/SDL_syswm.h>
#include "v4l2uvc.h"
#include "gui.h"
#include "utils.h"
#include "color.h"
/* Fixed point arithmetic */
#define FIXED Sint32
#define FIXED_BITS 16
#define TO_FIXED(X) (((Sint32)(X))<<(FIXED_BITS))
#define FROM_FIXED(X) (((Sint32)(X))>>(FIXED_BITS))

#define INCPANTILT 64 // 1°

typedef enum action_gui {
/* 0..7..15 action top */
    A_BRIGHTNESS_UP,
    A_CONTRAST_UP,
    A_SATURATION_UP,
    A_GAIN_UP,
    A_SHARPNESS_UP,
    A_GAMMA_UP,
    A_SCREENSHOT,
    A_RESET,
    A_PAN_UP,
    A_TILT_UP,
    A_PAN_RESET,
    A_SWITCH_LIGHTFREQFILT,
    A_EXPOSURE_UP,
    A_EXPOSURE_ON,
    A_BALANCE_UP,
    A_BALANCE_ON,
/* 8..15 -> 16..31 action bottom */
    A_BRIGHTNESS_DOWN,
    A_CONTRAST_DOWN,
    A_SATURATION_DOWN,
    A_GAIN_DOWN,
    A_SHARPNESS_DOWN,
    A_GAMMA_DOWN,
    A_RECORD_TOGGLE,
    A_QUIT,
    A_PAN_DOWN,
    A_TILT_DOWN,
    A_TILT_RESET,
    A_NOT1_DOWN,
    A_EXPOSURE_DOWN,
    A_EXPOSURE_OFF,
    A_BALANCE_DOWN,
    A_BALANCE_OFF,
/* 16.. action others */
    A_VIDEO,
    A_CAPTURE_FRAME,
    A_CAPTURE_STREAM,
    A_CAPTURE_FRAMESTREAM,
    A_SAVE,
    A_LOAD,
    A_LAST
} action_gui;

typedef struct act_title {
	action_gui action;
	char * title;
} act_title;

typedef struct key_action_t {
    SDLKey key;
    action_gui action;
} key_action_t;

key_action_t keyaction[] = {
    {SDLK_n, A_BRIGHTNESS_UP},
    {SDLK_b, A_BRIGHTNESS_DOWN},
    {SDLK_x, A_CONTRAST_UP},
    {SDLK_w, A_CONTRAST_DOWN},
    {SDLK_c, A_SATURATION_UP},
    {SDLK_v, A_SATURATION_DOWN},
    {SDLK_z, A_GAIN_UP},
    {SDLK_a, A_GAIN_DOWN},
    {SDLK_r, A_SHARPNESS_UP},
    {SDLK_e, A_SHARPNESS_DOWN},
    {SDLK_y, A_PAN_UP},
    {SDLK_t, A_PAN_DOWN},
    {SDLK_s, A_SCREENSHOT},
    {SDLK_p, A_RECORD_TOGGLE},
    {SDLK_f, A_SWITCH_LIGHTFREQFILT},
    {SDLK_l, A_RESET},
    {SDLK_q, A_QUIT},
    {SDLK_m, A_VIDEO},
    {SDLK_f, A_CAPTURE_FRAME},
    {SDLK_i, A_CAPTURE_STREAM},
    {SDLK_j, A_CAPTURE_FRAMESTREAM},
    {SDLK_F1, A_SAVE},
    {SDLK_F2, A_LOAD}    
};
act_title title_act[A_LAST] ={
/* 0..7..15 action top */
   { A_BRIGHTNESS_UP,"Brightness Up"},
   { A_CONTRAST_UP,"Contrast Up"},
   { A_SATURATION_UP,"Saturation Up"},
   { A_GAIN_UP,"Gain_Up"},
   { A_SHARPNESS_UP,"Sharpness Up"},
   { A_GAMMA_UP,"Gamma Up"},
   { A_SCREENSHOT,"Take a Picture!!"},
   { A_RESET,"Reset All to Default !!"},
   { A_PAN_UP,"Pan +angle"},
   { A_TILT_UP,"Tilt +angle"},
   { A_PAN_RESET,"Pan reset"},
   { A_SWITCH_LIGHTFREQFILT,"Switch light freq filter"},
   { A_EXPOSURE_UP,"Exposure Up"},
   { A_EXPOSURE_ON,"Auto Exposure On"},
   { A_BALANCE_UP,"White Balance Up"},
   { A_BALANCE_ON,"Auto White Balance On"},
/* 8..15 -> 16..31 action bottom */
   { A_BRIGHTNESS_DOWN,"Brightness Down"},
   { A_CONTRAST_DOWN,"Contrast Down"},
   { A_SATURATION_DOWN,"Saturation Down"},
   { A_GAIN_DOWN,"Gain Down"},
   { A_SHARPNESS_DOWN,"Sharpness Down"},
   { A_GAMMA_DOWN,"Gamma Down"},
   { A_RECORD_TOGGLE,"AVI Start/Stop"},
   { A_QUIT,"Quit Happy, Bye Bye:)"},
   { A_PAN_DOWN,"Pan -angle"},
   { A_TILT_DOWN,"Tilt -angle"},
   { A_TILT_RESET,"Tilt Reset"},
   { A_NOT1_DOWN,"Nothing"},
   { A_EXPOSURE_DOWN,"Exposure Down"},
   { A_EXPOSURE_OFF,"Auto Exposure OFF"},
   { A_BALANCE_DOWN,"White Balance Down"},
   { A_BALANCE_OFF,"Auto White Balance OFF"},
/* 16.. action others */
   { A_VIDEO,"LUVCview (c) Michel Xhaard"},
   { A_CAPTURE_FRAME, "Single frame captured" },
   { A_CAPTURE_STREAM, "Stream capture" },
   { A_CAPTURE_FRAMESTREAM, "Frame stream capture" },
   { A_SAVE, "Saved Configuration" },
   { A_LOAD, "Restored Configuration" }
};
static const char version[] = VERSION;
struct vdIn *videoIn;

/* Translates screen coordinates into buttons */
action_gui
GUI_whichbutton(int x, int y, SDL_Surface * pscreen, struct vdIn *videoIn);

action_gui GUI_keytoaction(SDLKey key);

struct pt_data {
    SDL_Surface **ptscreen;
    SDL_Event *ptsdlevent;
    SDL_Rect *drect;
    struct vdIn *ptvideoIn;
    unsigned char frmrate;
    SDL_mutex *affmutex;
} ptdata;

static int eventThread(void *data);
static Uint32 SDL_VIDEO_Flags =
    SDL_ANYFORMAT | SDL_DOUBLEBUF | SDL_RESIZABLE;
    

int main(int argc, char *argv[])
{
	const SDL_VideoInfo *info;
	char driver[128];
	SDL_Surface *pscreen;
	SDL_Overlay *overlay;
	SDL_Rect drect;
	SDL_Event sdlevent;
	SDL_Thread *mythread;
	SDL_mutex *affmutex;

	int status;
	Uint32 currtime;
	Uint32 lasttime;
	unsigned char *p = NULL;
	int hwaccel = 0;
	const char *videodevice = NULL;
	const char *mode = NULL;
	int format = V4L2_PIX_FMT_MJPEG;
	int i;
	int grabmethod = 1;
	int width = 640;
	int height = 480;
	int fps = 30;
	unsigned char frmrate = 0;
	char *avifilename = NULL;
	int queryformats = 0;
	int querycontrols = 0;
	int readconfigfile = 0;
	char *separateur;
	char *sizestring = NULL;
	char *fpsstring  = NULL;
	int enableRawStreamCapture = 0;
	int enableRawFrameCapture = 0;

	printf("luvcview %s\n\n", version);
	for (i = 1; i < argc; i++) {
		/* skip bad arguments */
		if (argv[i] == NULL || *argv[i] == 0 || *argv[i] != '-') {
			continue;
		}
		if (strcmp(argv[i], "-d") == 0) {
			if (i + 1 >= argc) {
				printf("No parameter specified with -d, aborting.\n");
				exit(1);
			}
			videodevice = strdup(argv[i + 1]);
		}
		if (strcmp(argv[i], "-g") == 0) {
			/* Ask for read instead default  mmap */
			grabmethod = 0;
		}
		if (strcmp(argv[i], "-w") == 0) {
			/* disable hw acceleration */
			hwaccel = 1;
		}
		if (strcmp(argv[i], "-f") == 0) {
			if (i + 1 >= argc) {
				printf("No parameter specified with -f, aborting.\n");
				exit(1);
			}
			mode = argv[i + 1];

			if (strcasecmp(mode, "yuv") == 0 || strcasecmp(mode, "YUYV") == 0) {
				format = V4L2_PIX_FMT_YUYV;
			} else if (strcasecmp(mode, "jpg") == 0 || strcasecmp(mode, "MJPG") == 0) {
				format = V4L2_PIX_FMT_MJPEG;
			} else {
				printf("Unknown format specified. Aborting.\n");
				exit(1);
			}
		}
		if (strcmp(argv[i], "-s") == 0) {
			if (i + 1 >= argc) {
				printf("No parameter specified with -s, aborting.\n");
				exit(1);
			}

			sizestring = strdup(argv[i + 1]);

			width = strtoul(sizestring, &separateur, 10);
			if (*separateur != 'x') {
				printf("Error in size use -s widthxheight\n");
				exit(1);
			} else {
				++separateur;
				height = strtoul(separateur, &separateur, 10);
				if (*separateur != 0)
					printf("hmm.. dont like that!! trying this height\n");
			}
		}
		if (strcmp(argv[i], "-i") == 0){
			if (i + 1 >= argc) {
				printf("No parameter specified with -i, aborting.\n");
				exit(1);
			}
			fpsstring = argv[i + 1];
			fps = strtoul(fpsstring, &separateur, 10);
			if(*separateur != '\0') {
				printf("Invalid frame rate '%s' specified with -i. "
						"Only integers are supported. Aborting.\n", fpsstring);
				exit(1);
			}
		}
		if (strcmp(argv[i], "-S") == 0) {
			/* Enable raw stream capture from the start */
			enableRawStreamCapture = 1;
		}
		if (strcmp(argv[i], "-c") == 0) {
			/* Enable raw frame capture for the first frame */
			enableRawFrameCapture = 1;
		}
		if (strcmp(argv[i], "-C") == 0) {
			/* Enable raw frame stream capture from the start*/
			enableRawFrameCapture = 2;
		}
		if (strcmp(argv[i], "-o") == 0) {
			/* set the avi filename */
			if (i + 1 >= argc) {
				printf("No parameter specified with -o, aborting.\n");
				exit(1);
			}
			avifilename = strdup(argv[i + 1]);
		}
		if (strcmp(argv[i], "-L") == 0) {
			/* query list of valid video formats */
			queryformats = 1;
		}
		if (strcmp(argv[i], "-l") == 0) {
			/* query list of valid video formats */
			querycontrols = 1;
		}

		if (strcmp(argv[i], "-r") == 0) {
			/* query list of valid video formats */
			readconfigfile = 1;
		}
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			printf("usage: uvcview [-h -d -g -f -s -i -c -o -C -S -L -l -r]\n");
			printf("-h	print this message\n");
			printf("-d	/dev/videoX       use videoX device\n");
			printf("-g	use read method for grab instead mmap\n");
			printf("-w	disable SDL hardware accel.\n");
			printf("-f	choose video format (YUYV/yuv and MJPG/jpg are valid, MJPG is default)\n");
			printf("-i	fps           use specified frame interval\n");
			printf("-s	widthxheight      use specified input size\n");
			printf("-c	enable raw frame capturing for the first frame\n");
			printf("-C	enable raw frame stream capturing from the start\n");
			printf("-S	enable raw stream capturing from the start\n");
			printf("-o	avifile  create avifile, default video.avi\n");
			printf("-L	query valid video formats\n");
			printf("-l	query valid controls and settings\n");
			printf("-r	read and set control settings from luvcview.cfg\n");
			exit(0);
		}
	}

	/************* Test SDL capabilities ************/
	if (SDL_Init(SDL_INIT_VIDEO) < 0) {
		fprintf(stderr, "Couldn't initialize SDL: %s\n", SDL_GetError());
		exit(1);
	}

	/* For this version, we'll be save and disable hardware acceleration */
	if(hwaccel)
		if ( ! getenv("SDL_VIDEO_YUV_HWACCEL") ) {
			putenv("SDL_VIDEO_YUV_HWACCEL=0");
		}

	printf("SDL information:\n");
	if (SDL_VideoDriverName(driver, sizeof(driver))) {
		printf("  Video driver: %s\n", driver);
	}
	info = SDL_GetVideoInfo();

	if (info->wm_available) {
		printf("  A window manager is available\n");
	}
	if (info->hw_available) {
		printf("  Hardware surfaces are available (%dk video memory)\n",
				info->video_mem);
		SDL_VIDEO_Flags |= SDL_HWSURFACE;
	}
	if (info->blit_hw) {
		printf("  Copy blits between hardware surfaces are accelerated\n");
		SDL_VIDEO_Flags |= SDL_ASYNCBLIT;
	}
	if (info->blit_hw_CC) {
		printf
			("  Colorkey blits between hardware surfaces are accelerated\n");
	}
	if (info->blit_hw_A) {
		printf("  Alpha blits between hardware surfaces are accelerated\n");
	}
	if (info->blit_sw) {
		printf
			("  Copy blits from software surfaces to hardware surfaces are accelerated\n");
	}
	if (info->blit_sw_CC) {
		printf
			("  Colorkey blits from software surfaces to hardware surfaces are accelerated\n");
	}
	if (info->blit_sw_A) {
		printf
			("  Alpha blits from software surfaces to hardware surfaces are accelerated\n");
	}
	if (info->blit_fill) {
		printf("  Color fills on hardware surfaces are accelerated\n");
	}

	if (!(SDL_VIDEO_Flags & SDL_HWSURFACE))
		SDL_VIDEO_Flags |= SDL_SWSURFACE;

	if (videodevice == NULL || *videodevice == 0) {
		videodevice = "/dev/video0";
	}

	if (avifilename == NULL || *avifilename == 0) {
		avifilename = "video.avi";
	}

	videoIn = (struct vdIn *) calloc(1, sizeof(struct vdIn));
	if ( queryformats ) {
		/* if we're supposed to list the video formats, do that now and go out */
		check_videoIn(videoIn,(char *) videodevice);
		free(videoIn);
		SDL_Quit();
		exit(1);
	}
	if (init_videoIn
			(videoIn, (char *) videodevice, width, height, fps, format,
			 grabmethod, avifilename) < 0)
		exit(1);
	/* if we're supposed to list the controls, do that now */
	if ( querycontrols )
		enum_controls(videoIn->fd);

	/* if we're supposed to read the control settings from a configfile, do that now */
	if ( readconfigfile )
		load_controls(videoIn->fd);

	pscreen =
		SDL_SetVideoMode(videoIn->width, videoIn->height + 32, 0,
				SDL_VIDEO_Flags);

	overlay =
		SDL_CreateYUVOverlay(videoIn->width, videoIn->height + 32,
				SDL_YUY2_OVERLAY, pscreen);
	p = (unsigned char *) overlay->pixels[0];
	drect.x = 0;
	drect.y = 0;
	drect.w = pscreen->w;
	drect.h = pscreen->h;
	if (enableRawStreamCapture) {
		videoIn->captureFile = fopen("stream.raw", "wb");
		if(videoIn->captureFile == NULL) {
			perror("Unable to open file for raw stream capturing");
		} else {
			printf("Starting raw stream capturing to stream.raw ...\n");
		}
	}
	if (enableRawFrameCapture)
		videoIn->rawFrameCapture = enableRawFrameCapture;
	initLut();
	SDL_WM_SetCaption(title_act[A_VIDEO].title, NULL);
	lasttime = SDL_GetTicks();
	creatButt(videoIn->width, 32);
	SDL_LockYUVOverlay(overlay);
	memcpy(p + (videoIn->width * (videoIn->height) * 2), YUYVbutt,
			videoIn->width * 64);
	SDL_UnlockYUVOverlay(overlay);
	/* initialize thread data */
	ptdata.ptscreen = &pscreen;
	ptdata.ptvideoIn = videoIn;
	ptdata.ptsdlevent = &sdlevent;
	ptdata.drect = &drect;
	affmutex = SDL_CreateMutex();
	ptdata.affmutex = affmutex;
	mythread = SDL_CreateThread(eventThread, (void *) &ptdata);
	/* main big loop */
	while (videoIn->signalquit) {
		currtime = SDL_GetTicks();
		if (currtime - lasttime > 0) {
			frmrate = 1000/(currtime - lasttime);
		}
		lasttime = currtime;
		if (uvcGrab(videoIn) < 0) {
			printf("Error grabbing\n");
			break;
		}

		/* if we're grabbing video, show the frame rate */
		if (videoIn->toggleAvi)
			printf("\rframe rate: %d     ",frmrate);

		SDL_LockYUVOverlay(overlay);
		memcpy(p, videoIn->framebuffer,
				videoIn->width * (videoIn->height) * 2);
		SDL_UnlockYUVOverlay(overlay);
		SDL_DisplayYUVOverlay(overlay, &drect);

		if (videoIn->getPict) { 
			switch(videoIn->formatIn){
				case V4L2_PIX_FMT_MJPEG:
					get_picture(videoIn->tmpbuffer,videoIn->buf.bytesused);
					break;
				case V4L2_PIX_FMT_YUYV:
					get_pictureYV2(videoIn->framebuffer,videoIn->width,videoIn->height);
					break;
				default:
					break;
			}
			videoIn->getPict = 0;
			printf("get picture !\n");
		}

		SDL_LockMutex(affmutex);
		ptdata.frmrate = frmrate;
		SDL_WM_SetCaption(videoIn->status, NULL);
		SDL_UnlockMutex(affmutex);
		SDL_Delay(10);

	}
	SDL_WaitThread(mythread, &status);
	SDL_DestroyMutex(affmutex);

	/* if avifile is defined, we made a video: compute the exact fps and
	   set it in the video */
	if (videoIn->avifile != NULL) {
		float fps=(videoIn->framecount/(videoIn->recordtime/1000));
		fprintf(stderr,"setting fps to %f\n",fps);
		AVI_set_video(videoIn->avifile, videoIn->width, videoIn->height,
				fps, "MJPG");
		AVI_close(videoIn->avifile);
	}

	close_v4l2(videoIn);
	free(videoIn);
	destroyButt();
	freeLut();
	printf("Cleanup done. Exiting ...\n");
	SDL_Quit();
}

action_gui
GUI_whichbutton(int x, int y, SDL_Surface * pscreen, struct vdIn *videoIn)
{
    int nbutton, retval;
    FIXED scaleh = TO_FIXED(pscreen->h) / (videoIn->height + 32);
    int nheight = FROM_FIXED(scaleh * videoIn->height);
    if (y < nheight)
	return (A_VIDEO);
    nbutton = FROM_FIXED(scaleh * 32);
    /* 8 buttons across the screen, corresponding to 0-7 extand to 16*/
    retval = (x * 16) / (pscreen->w);
    /* Bottom half of the button denoted by flag|0x10 */
    if (y > (nheight + (nbutton / 2)))
	retval |= 0x10;
    return ((action_gui) retval);
}

action_gui GUI_keytoaction(SDLKey key)
{
	int i = 0;
	while(keyaction[i].key){
		if (keyaction[i].key == key)
			return (keyaction[i].action);
		i++;
	}

	return (A_VIDEO);
}

static int eventThread(void *data)
{
	struct pt_data *gdata = (struct pt_data *) data;
	struct v4l2_control control;
	SDL_Surface *pscreen = *gdata->ptscreen;
	struct vdIn *videoIn = gdata->ptvideoIn;
	SDL_Event *sdlevent = gdata->ptsdlevent;
	SDL_Rect *drect = gdata->drect;
	SDL_mutex *affmutex = gdata->affmutex;
	unsigned char frmrate;
	int x, y;
	int mouseon = 0;
	int value = 0;
	int len = 0;
	short incpantilt = INCPANTILT;
	int boucle = 0;
	action_gui curr_action = A_VIDEO;
	while (videoIn->signalquit) {
		SDL_LockMutex(affmutex);
		frmrate = gdata->frmrate;
		while (SDL_PollEvent(sdlevent)) {	//scan the event queue
			switch (sdlevent->type) {
				case SDL_KEYUP:
				case SDL_MOUSEBUTTONUP:
					mouseon = 0;
					incpantilt = INCPANTILT;
					boucle = 0;
					break;
				case SDL_MOUSEBUTTONDOWN:
					mouseon = 1;
				case SDL_MOUSEMOTION:
					SDL_GetMouseState(&x, &y);
					curr_action = GUI_whichbutton(x, y, pscreen, videoIn);
					break;
				case SDL_VIDEORESIZE:
					pscreen =
						SDL_SetVideoMode(sdlevent->resize.w,
								sdlevent->resize.h, 0,
								SDL_VIDEO_Flags);
					drect->w = sdlevent->resize.w;
					drect->h = sdlevent->resize.h;
					break;
				case SDL_KEYDOWN:
					curr_action = GUI_keytoaction(sdlevent->key.keysym.sym);
					if (curr_action != A_VIDEO)
						mouseon = 1;
					break;
				case SDL_QUIT:
					printf("\nQuit signal received.\n");
					videoIn->signalquit = 0;
					break;
			}
		}			//end if poll
		SDL_UnlockMutex(affmutex);
		/* traiter les actions */
		value = 0;
		if (mouseon){
			boucle++;
			switch (curr_action) {
				case A_BRIGHTNESS_UP:  
					if ((value = v4l2UpControl(videoIn, V4L2_CID_BRIGHTNESS)) < 0)
						printf("Set Brightness up error\n");
					break;
				case A_CONTRAST_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_CONTRAST)) < 0)
						printf("Set Contrast up error\n");
					break;
				case A_SATURATION_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_SATURATION)) < 0)
						printf("Set Saturation up error\n");
					break;
				case A_GAIN_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_GAIN)) < 0)
						printf("Set Gain up error\n");
					break;
				case A_SHARPNESS_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_SHARPNESS)) < 0)
						printf("Set Sharpness up error\n");
					break;
				case A_GAMMA_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_GAMMA)) < 0)
						printf("Set Gamma up error\n");
					break;

				/* Motor control events */
				case A_PAN_UP:
					if ((value = v4L2UpDownPan(videoIn, -incpantilt)) < 0)
						printf("Set Pan up error\n");
					break;
				case A_PAN_DOWN: 
					if ((value = v4L2UpDownPan(videoIn, incpantilt)) < 0)	    
						printf("Set Pan down error\n");
					break;
				case A_TILT_UP:
					if ((value = v4L2UpDownTilt(videoIn, -incpantilt)) < 0)
						printf("Set Tilt up error\n");
					break;
				case A_TILT_DOWN: 
					if ((value = v4L2UpDownTilt(videoIn, incpantilt)) < 0)	    
						printf("Set Tilt down error\n");
					break;
				case A_PAN_RESET:
					if (v4l2ResetPan(videoIn) < 0)
						printf("Reset pan error\n");
					break;
				case A_TILT_RESET:
					if (v4l2ResetTilt(videoIn) < 0)
						printf("Reset tilt error\n");
					break;

				case A_SCREENSHOT:
					SDL_Delay(200);
					videoIn->getPict = 1;
					value = 1;
					break;
				case A_RESET:
					if (v4l2ResetControl(videoIn, V4L2_CID_BRIGHTNESS) < 0)
						printf("reset Brightness error\n");
					if (v4l2ResetControl(videoIn, V4L2_CID_SATURATION) < 0)
						printf("reset Saturation error\n");
					if (v4l2ResetControl(videoIn, V4L2_CID_CONTRAST) < 0)
						printf("reset Contrast error\n");
					if (v4l2ResetControl(videoIn, V4L2_CID_HUE) < 0)
						printf("reset Hue error\n");
					if (v4l2ResetControl(videoIn, V4L2_CID_SHARPNESS) < 0)
						printf("reset Sharpness error\n");
					if (v4l2ResetControl(videoIn, V4L2_CID_GAMMA) < 0)
						printf("reset Gamma error\n");
					if (v4l2ResetControl(videoIn, V4L2_CID_GAIN) < 0)
						printf("reset Gain error\n");
					if (v4l2ResetPanTilt(videoIn) < 0)
						printf("reset pantilt error\n");
					break;

				case A_BRIGHTNESS_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_BRIGHTNESS)) < 0)
						printf("Set Brightness down error\n");
					break;
				case A_CONTRAST_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_CONTRAST)) < 0)
						printf("Set Contrast down error\n");
					break;
				case A_SATURATION_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_SATURATION)) < 0)
						printf("Set Saturation down error\n");
					break;
				case A_GAIN_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_GAIN)) < 0)
						printf("Set Gain down error\n");
					break;
				case A_SHARPNESS_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_SHARPNESS)) < 0)
						printf("Set Sharpness down error\n");
					break;
				case A_GAMMA_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_GAMMA)) < 0)
						printf("Set Gamma down error\n");
					break;   
				case A_RECORD_TOGGLE:
					SDL_Delay(200);
					videoIn->toggleAvi = !videoIn->toggleAvi;
					value = videoIn->toggleAvi;
					if ( value == 1 ) {
						printf("avi recording started\n");
						videoIn->recordstart=SDL_GetTicks();
					}
					else {
						int dur=SDL_GetTicks()-videoIn->recordstart;
						printf("\navi recording stopped (%ds)\n",dur/1000);
						videoIn->recordtime+=dur;
					}
					break;
				case A_SWITCH_LIGHTFREQFILT: 
					if ((value =v4l2GetControl(videoIn,V4L2_CID_POWER_LINE_FREQUENCY)) < 0)	    
						printf("Get value of light frequency filter error\n");

					if(value < 2) // round switch 50->60->NoFliker->.
						value++;   //		 \_______________; 
					else
						value=0;

					if(value == 0)
						printf("Current light frequency filter: 50Hz\n");
					else if(value == 1)
						printf("Current light frequency filter: 60Hz\n");
					else if(value == 2)
						printf("Current light frequency filter: NoFliker\n");

					if ((value =v4l2SetLightFrequencyFilter(videoIn,value)) < 0)	    
						printf("Switch light frequency filter error\n");
					break;
				case A_QUIT:  
					videoIn->signalquit = 0;
					break;
				case A_VIDEO:
					break;
				case A_CAPTURE_FRAME:
					value = 1;
					videoIn->rawFrameCapture = 1;
					break;
				case A_CAPTURE_FRAMESTREAM:
					value = 1;
					if (!videoIn->rawFrameCapture) {
						videoIn->rawFrameCapture = 2;
						videoIn->rfsBytesWritten = 0;
						videoIn->rfsFramesWritten = 0;
						printf("Starting raw frame stream capturing ...\n");
					} else if(videoIn->framesWritten >= 5) {
						videoIn->rawFrameCapture = 0;
						printf("Stopped raw frame stream capturing. %u bytes written for %u frames.\n",
								videoIn->rfsBytesWritten, videoIn->rfsFramesWritten);
					}
					break;
				case A_CAPTURE_STREAM:
					value = 1;
					if (videoIn->captureFile == NULL) {
						videoIn->captureFile = fopen("stream.raw", "wb");
						if(videoIn->captureFile == NULL) {
							perror("Unable to open file for raw stream capturing");
						} else {
							printf("Starting raw stream capturing to stream.raw ...\n");
						}
						videoIn->bytesWritten = 0;
						videoIn->framesWritten = 0;
					} else if(videoIn->framesWritten >= 5) {
						fclose(videoIn->captureFile);
						printf("Stopped raw stream capturing to stream.raw. %u bytes written for %u frames.\n",
								videoIn->bytesWritten, videoIn->framesWritten);
						videoIn->captureFile = NULL;
					}
					break;
				case A_EXPOSURE_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_EXPOSURE_ABSOLUTE)) < 0)
						printf("Set Absolute Exposure up error\n");
					break;
				case A_EXPOSURE_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_EXPOSURE_ABSOLUTE)) < 0)
						printf("Set Absolute Exposure down error\n");
					break;
				case A_EXPOSURE_ON:
					control.id    =V4L2_CID_EXPOSURE_AUTO;
					control.value =1;
					if ((value = ioctl(videoIn->fd, VIDIOC_S_CTRL, &control)) < 0)
						printf("Set Auto Exposure on error\n");
					else
						printf("Auto Exposure set to %d\n", control.value);
					break;
				case A_EXPOSURE_OFF:
					control.id    =V4L2_CID_EXPOSURE_AUTO;
					control.value =8;
					if ((value = ioctl(videoIn->fd, VIDIOC_S_CTRL, &control)) < 0)
						printf("Set Auto Exposure off error\n");
					else
						printf("Auto Exposure set to %d\n", control.value);
					break;
				case A_BALANCE_UP:
					if ((value = v4l2UpControl(videoIn, V4L2_CID_WHITE_BALANCE_TEMPERATURE)) < 0)
						printf("Set Balance Temperature up error\n");
					break;
				case A_BALANCE_DOWN:
					if ((value = v4l2DownControl(videoIn, V4L2_CID_WHITE_BALANCE_TEMPERATURE)) < 0)
						printf("Set Balance Temperature down error\n");
					break;
				case A_BALANCE_ON:
					control.id    =V4L2_CID_AUTO_WHITE_BALANCE;
					control.value =1;
					if ((value = ioctl(videoIn->fd, VIDIOC_S_CTRL, &control)) < 0)
						printf("Set Auto Balance on error\n");
					else
						printf("Auto Balance set to %d\n", control.value);
					break;
				case A_BALANCE_OFF:
					control.id    =V4L2_CID_AUTO_WHITE_BALANCE;
					control.value =0;
					if ((value = ioctl(videoIn->fd, VIDIOC_S_CTRL, &control)) < 0)
						printf("Set Auto Balance off error\n");
					else
						printf("Auto Balance set to %d\n", control.value);
					break;
				case A_SAVE:
					printf("Save controls\n");
					save_controls(videoIn->fd);
					break;
				case A_LOAD:
					printf("load controls\n");
					load_controls(videoIn->fd);
					break;
				default:
					break;
			}
			if(!(boucle%10)) // smooth pan tilt method
				if(incpantilt < (10*INCPANTILT))
					incpantilt += (INCPANTILT/4);
			if(value){
				len = strlen(title_act[curr_action].title)+8;
				snprintf(videoIn->status, len,"%s %06d",title_act[curr_action].title,value);
			}
		} else { // mouseon

			len = strlen(title_act[curr_action].title)+9;
			snprintf(videoIn->status, len,"%s, %02d Fps",title_act[curr_action].title, frmrate);

		}
		SDL_Delay(50);
		//printf("fp/s %d\n",frmrate);
	}				//end main loop

	/* Close the stream capture file */
	if (videoIn->captureFile) {
		fclose(videoIn->captureFile);
		printf("Stopped raw stream capturing to stream.raw. %u bytes written for %u frames.\n",
				videoIn->bytesWritten, videoIn->framesWritten);
	}
	/* Display stats for raw frame stream capturing */
	if (videoIn->rawFrameCapture == 2) {
		printf("Stopped raw frame stream capturing. %u bytes written for %u frames.\n",
				videoIn->rfsBytesWritten, videoIn->rfsFramesWritten);
	}
}
