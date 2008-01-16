#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#if defined(__DECC) && defined(VMS)
#  include <X11/extensions/ipc.h>
#  include <X11/extensions/shm.h>
#else
#  include <sys/ipc.h>
#  include <sys/shm.h>
#endif
#include <X11/extensions/XShm.h>
#include <X11/extensions/Xv.h>
#include <X11/extensions/Xvlib.h>
#include "effect.h"
#include "blit/pixel_defs.h"
#include "sysdep/sysdep_display_priv.h"
#include "x11.h"

/* we need MITSHM! */
#ifndef USE_MITSHM
#error "USE_XV defined but USE_MITSHM is not defined, XV needs MITSHM!"
#endif

static void xv_update_16_to_YV12 (mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);
static void xv_update_16_to_YV12_perfect (mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);
static void xv_update_32_to_YV12_direct (mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);
static void xv_update_32_to_YV12_direct_perfect (mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/* options initialiased through the rc_option struct */
static int hwscale_force_yuv;
static int hwscale_perfect_yuv;

/* local vars */
static GC gc;
static int xv_format;
static XShmSegmentInfo shm_info;
static blit_func_p xv_update_display_func;
static char *hwscale_yv12_rotate_buf0=NULL;
static char *hwscale_yv12_rotate_buf1=NULL;
static XvImage *xvimage = NULL;
static int xv_port=-1;
static int mit_shm_attached = 0;

struct rc_option xv_opts[] = {
	/* name, shortname, type, dest, deflt, min, max, func, help */
	{ "XV Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL,  NULL },
	{ "force-yuv", NULL, rc_int, &hwscale_force_yuv, "0", 0, 2, NULL, "Force XV YUV mode:\n0 Autodetect\n1 Force YUY2\n2 Force YV12" },
	{ "perfect-yuv", NULL, rc_bool, &hwscale_perfect_yuv, "1", 0, 0, NULL, "Use perfect (slower) blitting code for XV YUV blits" },
	{ NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

static void xv_destroy_image(void);

static int FindXvPort(long format)
{
	int i,j,p,ret,num_formats;
	unsigned int num_adaptors;
	XvAdaptorInfo *ai;
	XvImageFormatValues *fo;

	ret = XvQueryAdaptors(display, DefaultRootWindow(display),
			&num_adaptors, &ai);

	if (ret != Success)
	{
		fprintf(stderr,"XV: QueryAdaptors failed\n");
		return 0;
	}

	for (i = 0; i < num_adaptors; i++)
	{
		for (p = ai[i].base_id; p < ai[i].base_id+ai[i].num_ports; p++)
		{
			fo = XvListImageFormats(display, p, &num_formats);
			for (j = 0; j < num_formats; j++)
			{
				if((fo[j].id==format))
				{
					if(XvGrabPort(display,p,CurrentTime)==Success)
					{
						xv_port=p;
						xv_format=format;
						sysdep_display_properties.palette_info.fourcc_format=format;
						sysdep_display_properties.palette_info.bpp=fo[j].bits_per_pixel;
						XFree(fo);
						XvFreeAdaptorInfo(ai);
						return 1;
					}
				}
			}
			XFree(fo);
		}
	}
	XvFreeAdaptorInfo(ai);
	return 0;
}

static int FindRGBXvFormat(void)
{
	int i,j,p,ret,num_formats;
	unsigned int num_adaptors;
	XvAdaptorInfo *ai;
	XvImageFormatValues *fo;

	ret = XvQueryAdaptors(display, DefaultRootWindow(display),
			&num_adaptors, &ai);

	if (ret != Success)
	{
		fprintf(stderr,"XV: QueryAdaptors failed\n");
		return 0;
	}

	for (i = 0; i < num_adaptors; i++)
	{
		int firstport=ai[i].base_id;
		int portcount=ai[i].num_ports;

		for (p = firstport; p < ai[i].base_id+portcount; p++)
		{
			fo = XvListImageFormats(display, p, &num_formats);
			for (j = 0; j < num_formats; j++)
			{
				if((fo[j].type==XvRGB) && (fo[j].format==XvPacked))
				{
					if(XvGrabPort(display,p,CurrentTime)==Success)
					{
						xv_port=p;
						xv_format=fo[j].id;
						sysdep_display_properties.palette_info.red_mask  =fo[j].red_mask;
						sysdep_display_properties.palette_info.green_mask=fo[j].green_mask;
						sysdep_display_properties.palette_info.blue_mask =fo[j].blue_mask;
						sysdep_display_properties.palette_info.depth=fo[j].depth;
						sysdep_display_properties.palette_info.bpp=fo[j].bits_per_pixel;
						XFree(fo);
						return 1;
					}
				}
			}
			XFree(fo);
		}
	}
	XvFreeAdaptorInfo(ai);
	return 0;
}

/* Since with YUV formats a field of zeros is generally
   loud green, rather than black, it makes sense
   to clear the image before use (since scanline algorithms
   leave alternate lines "black") */
static void ClearYUY2()
{
  int i,j;
  char *yuv;

  /* since we call sysdep_display_effect_open before creating the xvimage,
     we might get called without an image ! */
  if (!xvimage)
    return;
  
  fprintf(stderr,"Clearing YUY2\n");
  yuv=(xvimage->data+xvimage->offsets[0]);
  for (i = 0; i < xvimage->height; i++)
  {
    for (j = 0; j < xvimage->width; j++)
    {
      int offset=(xvimage->width*i+j)*2;
      yuv[offset] = 0;
      yuv[offset+1]=-128;
    }
  }
}

static void ClearYV12()
{
  int i,j;
  char *y, *u, *v;

  /* since we call sysdep_display_effect_open before creating the xvimage,
     we might get called without an image ! */
  if (!xvimage)
    return;
  
  fprintf(stderr,"Clearing YV12\n");
  y=(xvimage->data+xvimage->offsets[0]);
  u=(xvimage->data+xvimage->offsets[1]);
  v=(xvimage->data+xvimage->offsets[2]);
  for (i = 0; i < xvimage->height; i++) {
    for (j = 0; j < xvimage->width; j++) {
      int offset=(xvimage->width*i+j);
      y[offset] = 0;
      if((i&1) && (j&1))
      {
        offset = (xvimage->width/2)*(i/2) + (j/2);
        u[offset] = -128;
        v[offset] = -128;
      }
    }
  }
}

int xv_init(void)
{
  int i;
  unsigned int u;
  
  shm_info.shmaddr = NULL;
  
  if(XQueryExtension (display, "MIT-SHM", &i, &i, &i) &&
     (XvQueryExtension(display, &u, &u, &u, &u, &u)==Success))
    return SYSDEP_DISPLAY_WINDOWED|SYSDEP_DISPLAY_FULLSCREEN|
      SYSDEP_DISPLAY_HWSCALE|SYSDEP_DISPLAY_EFFECTS;

  fprintf (stderr, "X-Server Doesn't support MIT-SHM or Xv extension.\n"
    "Disabling use of Xv mode.\n");
  return 0;
}

/* This name doesn't really cover this function, since it also sets up mouse
   and keyboard. This is done over here, since on most display targets the
   mouse and keyboard can't be setup before the display has. */
int xv_open_display(int reopen)
{
	unsigned int height, width;

	if (!reopen)
	{
          int i, count;
  	  XGCValues xgcv;
          XvAttribute *attr;

	  /* Initial settings of the sysdep_display_properties struct,
             the FindXvXXX fucntions will fill in the palette part */
          sysdep_display_properties.max_width  = -1;
          sysdep_display_properties.max_height = -1;
          memset(&sysdep_display_properties.palette_info, 0, sizeof(struct
            sysdep_palette_info));
	  sysdep_display_properties.vector_renderer = NULL;

	  /* create a window */
	  if (x11_create_window(&window_width, &window_height,
	      X11_RESIZABLE_ASPECT))
            return 1;
          
          /* create gc */
          gc = XCreateGC (display, window, 0, &xgcv);

          fprintf (stderr, "MIT-SHM & XV Extensions Available. trying to use.\n");
          /* find a suitable format */
          switch(hwscale_force_yuv)
          {
            case 0: /* try normal RGB */
              if(FindRGBXvFormat())
                break;
              fprintf(stderr,"Can't find a suitable RGB format - trying YUY2 instead.\n");
            case 1: /* force YUY2 */
              if(FindXvPort(FOURCC_YUY2))
                break;
              fprintf(stderr,"YUY2 not available - trying YV12.\n");
            case 2: /* forced YV12 */
              if(FindXvPort(FOURCC_YV12))
                break;
              fprintf(stderr,"Error: Couldn't initialise Xv port - \n");
              fprintf(stderr,"  Either all ports are in use, or the video card\n");
              fprintf(stderr,"  doesn't provide a suitable format.\n");
              return 1;
          }

          attr = XvQueryPortAttributes(display, xv_port, &count);
          for (i = 0; i < count; i++)
          if (!strcmp(attr[i].name, "XV_AUTOPAINT_COLORKEY"))
          {
            Atom atom = XInternAtom(display, "XV_AUTOPAINT_COLORKEY", False);
            XvSetPortAttribute(display, xv_port, atom, 1);
            break;
          }

	  /* open xinput */
          xinput_open(0, 0);
        }
        else
        {
          sysdep_display_effect_close();
          x11_resize_window(&window_width, &window_height,
	    X11_RESIZABLE_ASPECT);
        }
        
        /* Now we have created the window we no longer need yarbsize,
           yarbsize may cause a warning in sysdep_display_effect_open,
           so clear it now! */
        sysdep_display_params.yarbsize = 0;
        
        /* handle special YV12 case */
        if(xv_format == FOURCC_YV12)
        {
          /* no effects */
          if (sysdep_display_params.effect)
          {
            fprintf(stderr,
              "Warning effect %s is not supported with color format YV12, disabling effects\n",
              sysdep_display_effect_properties[sysdep_display_params.effect].name);
            sysdep_display_params.effect = 0;
          }
          sysdep_display_set_up_rotation();
          if (sysdep_display_params.depth == 32)
          {
              if (hwscale_perfect_yuv)
                      xv_update_display_func
                              = xv_update_32_to_YV12_direct_perfect;
              else
                      xv_update_display_func
                              = xv_update_32_to_YV12_direct;
          }
          else
          {
              if (hwscale_perfect_yuv)
                      xv_update_display_func
                              = xv_update_16_to_YV12_perfect;
              else
                      xv_update_display_func
                              = xv_update_16_to_YV12;
          }
          /* YV12 always does normal scaling, no effects!.
             Setup the image size and scaling params for YV12:
             -align width and x-coordinates to 8, I don't know
              why, this is needed, but it is.
             -align height and y-coodinates to 2.
             Note these alignment demands are always met for
             perfect blit. */
          if (hwscale_perfect_yuv)
          {
            width  = 2*sysdep_display_params.max_width;
            height = 2*sysdep_display_params.max_height;
            sysdep_display_params.widthscale  = 2;
            sysdep_display_params.heightscale = 2;
          }
          else
          {
            width  = (sysdep_display_params.max_width+7)&~7;
            height = (sysdep_display_params.max_height+1)&~1;
            sysdep_display_params.widthscale  = 1;
            sysdep_display_params.heightscale = 1;
          }
        }
        else
        {
          int min_widthscale = (xv_format == FOURCC_YUY2)? 2:1;
          
          /* Get a blit function, do this first because this can change the
             effect settings und thus influence the size of the image we need
             to create */
          if (!(xv_update_display_func = sysdep_display_effect_open()))
            return 1;

          /* Set lowest widthscale / heightscale for the choisen effect. We
             deviate from the width- and heightscale settings choisen by the
             user because we can do some of the scaling in hardware */
          switch(sysdep_display_params.effect)
          {
            case SYSDEP_DISPLAY_EFFECT_NONE:
            case SYSDEP_DISPLAY_EFFECT_FAKESCAN_H:
              if (hwscale_perfect_yuv)
                sysdep_display_params.widthscale = min_widthscale;
              else
                sysdep_display_params.widthscale = 1;
              sysdep_display_params.heightscale =
                sysdep_display_effect_properties[sysdep_display_params.effect].
                  min_heightscale;
              break;
            case SYSDEP_DISPLAY_EFFECT_SCALE2X:
            case SYSDEP_DISPLAY_EFFECT_LQ2X:
            case SYSDEP_DISPLAY_EFFECT_HQ2X:
            case SYSDEP_DISPLAY_EFFECT_6TAP2X:
              sysdep_display_params.heightscale =
                sysdep_display_params.widthscale;
              break;
            case SYSDEP_DISPLAY_EFFECT_SCAN2_H:
            case SYSDEP_DISPLAY_EFFECT_SCAN3_H:
            case SYSDEP_DISPLAY_EFFECT_RGBSCAN_H:
              if (sysdep_display_effect_properties[
                    sysdep_display_params.effect].min_widthscale >
                  min_widthscale)
                sysdep_display_params.widthscale =
                  sysdep_display_effect_properties[
                    sysdep_display_params.effect].min_widthscale;
              else
                sysdep_display_params.widthscale = min_widthscale;
              break;
            case SYSDEP_DISPLAY_EFFECT_SCAN2_V:
            case SYSDEP_DISPLAY_EFFECT_SCAN3_V:
            case SYSDEP_DISPLAY_EFFECT_RGBSCAN_V:
              sysdep_display_params.heightscale = 1;
              break;
            case SYSDEP_DISPLAY_EFFECT_FAKESCAN_V:
              sysdep_display_params.widthscale  = min_widthscale;
              sysdep_display_params.heightscale = 1;
              break;
            default:
              fprintf(stderr,
                "Error unknown effect (%d) in xv.c, this should not happen.\n"
                "Please file a bug report\n", sysdep_display_params.effect);
              return 1;
          }
          /* Determine width and height for the image creation. */
          width  = sysdep_display_params.max_width *
            sysdep_display_params.widthscale;
          height = sysdep_display_params.max_height *
            sysdep_display_params.heightscale;
        }

        if (xvimage &&
            ((width  > xvimage->width ) ||
             (height > xvimage->height)))
          xv_destroy_image();

        if (!xvimage)
        {          
          /* Create an XV MITSHM image. */
          x11_mit_shm_error = 0;
          XSetErrorHandler (x11_test_mit_shm);
          xvimage = XvShmCreateImage (display,
                  xv_port,
                  xv_format,
                  0,
                  width,
                  height,
                  &shm_info);
          if (!xvimage)
          {
            fprintf(stderr, "Error creating XvShmImage.\n");
            return 1;
          }

          /* sometimes xv gives us a smaller image then we want ! */
          if ((xvimage->width  < width) ||
              (xvimage->height < height))
          {
            fprintf (stderr,
              "Error: XVimage is smaller then the requested size. (requested: %dx%d, got %dx%d)\n",
              width, height, xvimage->width, xvimage->height);
            return 1;
          }

          shm_info.readOnly = False;
          shm_info.shmid = shmget (IPC_PRIVATE,
                          xvimage->data_size,
                          (IPC_CREAT | 0777));
          if (shm_info.shmid < 0)
          {
                  fprintf (stderr, "Error: failed to create MITSHM block.\n");
                  return 1;
          }

          /* And allocate the bitmap buffer. */
          xvimage->data = shm_info.shmaddr =
                  (char *) shmat (shm_info.shmid, 0, 0);
          if (!xvimage->data)
          {
                  fprintf (stderr, "Error: failed to allocate MITSHM bitmap buffer.\n");
                  return 1;
          }

          /* Attach the MITSHM block. this will cause an exception if */
          /* MIT-SHM is not available. so trap it and process         */
          if (!XShmAttach (display, &shm_info))
          {
                  fprintf (stderr, "Error: failed to attach MITSHM block.\n");
                  return 1;
          }
          XSync (display, False);  /* be sure to get request processed */
          /* sleep (2);          enought time to notify error if any */
          /* Mark segment as deletable after we attach.  When all processes
             detach from the segment (progam exits), it will be deleted.
             This way it won't be left in memory if we crash or something.
             Grr, have todo this after X attaches too since slowlaris doesn't
             like it otherwise */
          shmctl(shm_info.shmid, IPC_RMID, NULL);

          if (x11_mit_shm_error)
          {
                  fprintf (stderr, "Error: failed to attach MITSHM block.\n");
                  return 1;
          }

          mit_shm_attached = 1;
            
          /* HACK, GRRR sometimes this all succeeds, but the first call to
             XvShmPutImage to a mapped window fails with:
             "BadAlloc (insufficient resources for operation)" */
          xv_clear_display_buffer();
          mode_clip_aspect(window_width, window_height, &width, &height);
          XvShmPutImage (display, xv_port, window, gc, xvimage,
            0, 0, xvimage->width, xvimage->height,
            (window_width-width)/2, (window_height-height)/2, width, height,
            True);
            
          XSync (display, False);  /* be sure to get request processed */
          /* sleep (1);          enought time to notify error if any */
          
          if (x11_mit_shm_error)
          {
                  fprintf(stderr, "XvShmPutImage failed, probably due to: \"BadAlloc (insufficient resources for operation)\"\n");
                  return 1;
          }
          XSetErrorHandler (None);  /* Restore error handler to default */

          if ((xv_format == FOURCC_YV12) && sysdep_display_params.orientation)
          {
                  hwscale_yv12_rotate_buf0=malloc(
                    ((sysdep_display_params.depth+7)/8)*
                    ((sysdep_display_params.max_width+7)&~7));
                  hwscale_yv12_rotate_buf1=malloc(
                    ((sysdep_display_params.depth+7)/8)*
                    ((sysdep_display_params.max_width+7)&~7));
                  if (!hwscale_yv12_rotate_buf0 ||
                      !hwscale_yv12_rotate_buf1)
                  {
                    fprintf (stderr, "Error: failed to allocate rotate buffer.\n");
                    return 1;
                  }
          }

          fprintf (stderr, "Using Xv & Shared Memory Features to speed up\n");
        }
 
	return 0;
}

/*
 * Shut down the display, also called by the core to clean up if any error
 * happens when creating the display.
 */
void xv_close_display (void)
{
   /* Restore error handler to default */
   XSetErrorHandler (None);

   /* close effects */
   sysdep_display_effect_close();
   
   /* ungrab keyb and mouse */
   xinput_close();

   /* now just free everything else */
   if (window)
   {
      XFreeGC(display, gc);
      XDestroyWindow (display, window);
      window = 0;
   }
   if(xv_port>-1)
   {
      XvUngrabPort(display,xv_port,CurrentTime);
      xv_port=-1;
   }
   xv_destroy_image();
   
   XSync (display, True); /* send all events to sync; discard events */
}

static void xv_destroy_image(void)
{
   if (mit_shm_attached)
   {
      XShmDetach (display, &shm_info);
      mit_shm_attached = 0;
   }
   if (shm_info.shmaddr)
   {
      shmdt (shm_info.shmaddr);
      shm_info.shmaddr = NULL;
   }
   if(xvimage)
   {
       XFree(xvimage);
       xvimage=NULL;
   }
   if (hwscale_yv12_rotate_buf0)
   {
      free (hwscale_yv12_rotate_buf0);
      hwscale_yv12_rotate_buf0 = NULL;
   }
   if (hwscale_yv12_rotate_buf1)
   {
      free (hwscale_yv12_rotate_buf1);
      hwscale_yv12_rotate_buf1 = NULL;
   }
}

/* invoked by main tree code to update bitmap into screen */
const char *xv_update_display(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, int flags)
{
  Window _dw;
  int _dint;
  unsigned int _duint;
  unsigned int pw,ph;
  rectangle vis_area = *vis_in_dest_out;

  sysdep_display_orient_bounds(&vis_area, bitmap->width, bitmap->height);

  xv_update_display_func(bitmap, vis_in_dest_out, dirty_area,
    palette, (unsigned char *)xvimage->data, xvimage->width);

  XGetGeometry(display, window, &_dw, &_dint, &_dint, &window_width, &window_height, &_duint, &_duint);
  if (sysdep_display_params.fullscreen || run_in_root_window)
  {
    mode_clip_aspect(window_width, window_height, &pw, &ph);
  }
  else
  {
    pw = window_width;
    ph = window_height;
  }
  XvShmPutImage (display, xv_port, window, gc, xvimage, 0, 0,
    (vis_area.max_x-vis_area.min_x) * sysdep_display_params.widthscale,
    (vis_area.max_y-vis_area.min_y) * sysdep_display_params.heightscale,
    (window_width-pw)/2, (window_height-ph)/2, pw, ph, True);

  /* some games "flickers" with XFlush, so command line option is provided */
  if (use_xsync)
    XSync (display, False);   /* be sure to get request processed */
  else
    XFlush (display);         /* flush buffer to server */
    
  return NULL;
}

void xv_clear_display_buffer(void)
{
  switch(sysdep_display_properties.palette_info.fourcc_format)
  {
    case FOURCC_YUY2:
      ClearYUY2();
      break;
    case FOURCC_YV12:
      ClearYV12();
      break;
    default:
      memset(xvimage->data, 0, xvimage->data_size);
  }
}

/* Hacked into place, until I integrate YV12 support into the blit core... */
static void xv_update_16_to_YV12(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width)
{
   int _x,_y;
   char *dest_y;
   char *dest_u;
   char *dest_v;
   unsigned short *src; 
   unsigned short *src2;
   int u1,v1,y1,u2,v2,y2,u3,v3,y3,u4,v4,y4;     /* 12 */
   
   sysdep_display_check_bounds(bitmap, vis_in_dest_out, dirty_area, 7);
   
   _y = vis_in_dest_out->min_y;
   vis_in_dest_out->min_y &= ~1;
   dirty_area->min_y -= _y - vis_in_dest_out->min_y;

   for(_y=dirty_area->min_y;_y<dirty_area->max_y;_y+=2)
   {
      if (sysdep_display_params.orientation)
      {
         rotate_func(hwscale_yv12_rotate_buf0, bitmap, _y, dirty_area);
         rotate_func(hwscale_yv12_rotate_buf1, bitmap, _y+1, dirty_area);
	 src  = (unsigned short*)hwscale_yv12_rotate_buf0;
	 src2 = (unsigned short*)hwscale_yv12_rotate_buf1;
      }
      else
      {
         src=bitmap->line[_y] ;
         src+= dirty_area->min_x;
         src2=bitmap->line[_y+1];
         src2+= dirty_area->min_x;
      }

      dest_y = (xvimage->data+xvimage->offsets[0]) +  xvimage->width*((_y-dirty_area->min_y)+vis_in_dest_out->min_y)    + vis_in_dest_out->min_x;
      dest_u = (xvimage->data+xvimage->offsets[2]) + (xvimage->width*((_y-dirty_area->min_y)+vis_in_dest_out->min_y))/4 + vis_in_dest_out->min_x/2;
      dest_v = (xvimage->data+xvimage->offsets[1]) + (xvimage->width*((_y-dirty_area->min_y)+vis_in_dest_out->min_y))/4 + vis_in_dest_out->min_x/2;

      for(_x=dirty_area->min_x;_x<dirty_area->max_x;_x+=2)
      {
            v1 = palette->lookup[*src++];
            y1 = (v1>>Y1SHIFT) & 0xff;
            u1 = (v1>>USHIFT)  & 0xff;
            v1 = (v1>>VSHIFT)  & 0xff;

            v2 = palette->lookup[*src++];
            y2 = (v2>>Y1SHIFT) & 0xff;
            u2 = (v2>>USHIFT)  & 0xff;
            v2 = (v2>>VSHIFT)  & 0xff;

            v3 = palette->lookup[*src2++];
            y3 = (v3>>Y1SHIFT) & 0xff;
            u3 = (v3>>USHIFT)  & 0xff;
            v3 = (v3>>VSHIFT)  & 0xff;

            v4 = palette->lookup[*src2++];
            y4 = (v4>>Y1SHIFT) & 0xff;
            u4 = (v4>>USHIFT)  & 0xff;
            v4 = (v4>>VSHIFT)  & 0xff;

         *dest_y = y1;
         *(dest_y++ + xvimage->width) = y3;
         *dest_y = y2;
         *(dest_y++ + xvimage->width) = y4;

         *dest_u++ = (u1+u2+u3+u4)/4;
         *dest_v++ = (v1+v2+v3+v4)/4;

         /* I thought that the following would be better, but it is not
          * the case. The color gets blurred
         if (y || y2 || y3 || y4) {
                 *dest_u++ = (u*y+u2*y2+u3*y3+u4*y4)/(y+y2+y3+y4);
                 *dest_v++ = (v*y+v2*y2+v3*y3+v4*y4)/(y+y2+y3+y4);
         } else {
                 *dest_u++ =128;
                 *dest_v++ =128;
         }
         */
      }
   }
}


static void xv_update_16_to_YV12_perfect(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width)
{      /* this one is used when scale==2 */
   unsigned int _x,_y;
   char *dest_y;
   char *dest_u;
   char *dest_v;
   unsigned short *src;
   int u1,v1,y1;

   sysdep_display_check_bounds(bitmap, vis_in_dest_out, dirty_area, 7);

   for(_y=dirty_area->min_y;_y<dirty_area->max_y;_y++)
   {
      if (sysdep_display_params.orientation)
      {
         rotate_func(hwscale_yv12_rotate_buf0, bitmap, _y, dirty_area);
         src = (unsigned short*)hwscale_yv12_rotate_buf0;
      }
      else
      {
         src=bitmap->line[_y] ;
         src+= dirty_area->min_x;
      }

      dest_y=(xvimage->data+xvimage->offsets[0])+2*xvimage->width*((_y-dirty_area->min_y)+(vis_in_dest_out->min_y/2))+vis_in_dest_out->min_x;
      dest_u=(xvimage->data+xvimage->offsets[2])+ (xvimage->width*((_y-dirty_area->min_y)+(vis_in_dest_out->min_y/2))+vis_in_dest_out->min_x)/2;
      dest_v=(xvimage->data+xvimage->offsets[1])+ (xvimage->width*((_y-dirty_area->min_y)+(vis_in_dest_out->min_y/2))+vis_in_dest_out->min_x)/2;
      for(_x=dirty_area->min_x;_x<dirty_area->max_x;_x++)
      {
            v1 = palette->lookup[*src++];
            y1 = (v1>>Y1SHIFT) & 0xff;
            u1 = (v1>>USHIFT)  & 0xff;
            v1 = (v1>>VSHIFT)  & 0xff;

         *(dest_y+xvimage->width)=y1;
         *dest_y++=y1;
         *(dest_y+xvimage->width)=y1;
         *dest_y++=y1;
         *dest_u++ = u1;
         *dest_v++ = v1;
      }
   }
}

static void xv_update_32_to_YV12_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width)
{
   int _x,_y,r,g,b;
   char *dest_y;
   char *dest_u;
   char *dest_v;
   unsigned int *src;
   unsigned int *src2;
   int u1,v1,y1,u2,v2,y2,u3,v3,y3,u4,v4,y4;     /* 12  34 */

   sysdep_display_check_bounds(bitmap, vis_in_dest_out, dirty_area, 7);

   _y = vis_in_dest_out->min_y;
   vis_in_dest_out->min_y &= ~1;
   dirty_area->min_y -= _y - vis_in_dest_out->min_y;

   for(_y=dirty_area->min_y;_y<dirty_area->max_y;_y+=2)
   {
      if (sysdep_display_params.orientation)
      {
         rotate_func(hwscale_yv12_rotate_buf0, bitmap, _y, dirty_area);
         rotate_func(hwscale_yv12_rotate_buf1, bitmap, _y+1, dirty_area);
         src  = (unsigned int*)hwscale_yv12_rotate_buf0;
         src2 = (unsigned int*)hwscale_yv12_rotate_buf1;
      }
      else
      {
         src=bitmap->line[_y] ;
         src+= dirty_area->min_x;
         src2=bitmap->line[_y+1];
         src2+= dirty_area->min_x;
      }

      dest_y = (xvimage->data+xvimage->offsets[0]) +  xvimage->width*((_y-dirty_area->min_y)+vis_in_dest_out->min_y)    + vis_in_dest_out->min_x;
      dest_u = (xvimage->data+xvimage->offsets[2]) + (xvimage->width*((_y-dirty_area->min_y)+vis_in_dest_out->min_y))/4 + vis_in_dest_out->min_x/2;
      dest_v = (xvimage->data+xvimage->offsets[1]) + (xvimage->width*((_y-dirty_area->min_y)+vis_in_dest_out->min_y))/4 + vis_in_dest_out->min_x/2;

      for(_x=dirty_area->min_x;_x<dirty_area->max_x;_x+=2)
      {
         b = *src++;
         r = (b>>16) & 0xFF;
         g = (b>>8)  & 0xFF;
         b = (b)     & 0xFF;
         RGB2YUV(r,g,b,y1,u1,v1);

         b = *src++;
         r = (b>>16) & 0xFF;
         g = (b>>8)  & 0xFF;
         b = (b)     & 0xFF;
         RGB2YUV(r,g,b,y2,u2,v2);

         b = *src2++;
         r = (b>>16) & 0xFF;
         g = (b>>8)  & 0xFF;
         b = (b)     & 0xFF;
         RGB2YUV(r,g,b,y3,u3,v3);

         b = *src2++;
         r = (b>>16) & 0xFF;
         g = (b>>8)  & 0xFF;
         b = (b)     & 0xFF;
         RGB2YUV(r,g,b,y4,u4,v4);

         *dest_y = y1;
         *(dest_y++ + xvimage->width) = y3;
         *dest_y = y2;
         *(dest_y++ + xvimage->width) = y4;
         *dest_u++ = (u1+u2+u3+u4)/4;
         *dest_v++ = (v1+v2+v3+v4)/4;
      }
   }
}

static void xv_update_32_to_YV12_direct_perfect(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width)
{ /* This one is used when scale == 2 */
   int _x,_y,r,g,b;
   char *dest_y;
   char *dest_u;
   char *dest_v;
   unsigned int *src;
   int u1,v1,y1;

   sysdep_display_check_bounds(bitmap, vis_in_dest_out, dirty_area, 7);

   for(_y=dirty_area->min_y;_y<dirty_area->max_y;_y++)
   {
      if (sysdep_display_params.orientation)
      {
         rotate_func(hwscale_yv12_rotate_buf0, bitmap, _y, dirty_area);
         src  = (unsigned int*)hwscale_yv12_rotate_buf0;
      }
      else
      {
         src=bitmap->line[_y] ;
         src+= dirty_area->min_x;
      }

      dest_y=(xvimage->data+xvimage->offsets[0])+2*xvimage->width*((_y-dirty_area->min_y)+(vis_in_dest_out->min_y/2))+vis_in_dest_out->min_x;
      dest_u=(xvimage->data+xvimage->offsets[2])+ (xvimage->width*((_y-dirty_area->min_y)+(vis_in_dest_out->min_y/2))+vis_in_dest_out->min_x)/2;
      dest_v=(xvimage->data+xvimage->offsets[1])+ (xvimage->width*((_y-dirty_area->min_y)+(vis_in_dest_out->min_y/2))+vis_in_dest_out->min_x)/2;
      for(_x=dirty_area->min_x;_x<dirty_area->max_x;_x++)
      {
         b = *src++;
         r = (b>>16) & 0xFF;
         g = (b>>8)  & 0xFF;
         b = (b)     & 0xFF;
         RGB2YUV(r,g,b,y1,u1,v1);

         *(dest_y+xvimage->width) = y1;
         *dest_y++ = y1;
         *(dest_y+xvimage->width) = y1;
         *dest_y++ = y1;
         *dest_u++ = u1;
         *dest_v++ = v1;
      }
   }
}
