/*
 *	XFree86 VidMode and DGA support by Jens Vaasjo <jvaasjo@iname.com>
 *      Modified for DGA 2.0 native API support
 *      by Shyouzou Sugitani <shy@debian.or.jp>
 *      Stea Greene <stea@cs.binghamton.edu>
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/xf86dga.h>
#include <X11/extensions/xf86vmode.h>
#include "sysdep/sysdep_display_priv.h"
#include "x11.h"

#ifdef X_XDGASetMode

#define TDFX_DGA_WORKAROUND

static struct
{
	int screen;
	unsigned char *addr;
	int width;
	Colormap cmap;
	blit_func_p update_display_func;
	XDGADevice *device;
	XDGAMode *modes;
	int mode_count;
	int current_mode;
	int aligned_viewport_height;
	int page;
	int max_page;
	int max_page_limit;
	int page_dirty;
	rectangle old_dirty_area;
#ifdef TDFX_DGA_WORKAROUND
	int current_X11_mode;
#endif
} xf86ctx = {-1,NULL,-1,0,NULL,NULL,NULL,0,-1,0,0,0,2,0,{0,0,0,0}};
	
struct rc_option xf86_dga2_opts[] = {
  /* name, shortname, type, dest, deflt, min, max, func, help */
  { "vsync-pagelimit", "vspl", rc_int, &(xf86ctx.max_page_limit), "2", 0, 16, NULL, "Maximum number of pages (frames) to queue in video memory for display after vsync" },
  { NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

static int xf86_dga2_set_mode(void);

int xf86_dga2_init(void)
{
	int i,j ;
	
	xf86ctx.screen           = DefaultScreen(display);
	
	if(!XDGAQueryVersion(display, &i, &j))
		fprintf(stderr,"XDGAQueryVersion failed\n");
	else if (i < 2)
		fprintf(stderr,"This driver requires DGA 2.0 or newer\n");
	else if(!XDGAQueryExtension(display, &i, &j))
		fprintf(stderr,"XDGAQueryExtension failed\n");
	else
	{
          /* Dumping core while DirectVideo is active causes an X-server
             freeze with kernel 2.6, so don't dump core! */
          struct rlimit limit = { 0, 0 };
          if(setrlimit(RLIMIT_CORE, &limit))
                  perror("rlimit");
          else if(!XDGAOpenFramebuffer(display,xf86ctx.screen))
                  fprintf(stderr,"XDGAOpenFramebuffer failed\n");
          else
                  return SYSDEP_DISPLAY_FULLSCREEN|SYSDEP_DISPLAY_EFFECTS;
        }
		
	fprintf(stderr,"Use of DGA-modes is disabled\n");
	return 0;
}

static int xf86_dga_vidmode_find_best_vidmode(void)
{
	int i;
	int bestmode = -1;
	int score, best_score = 0;

#ifdef TDFX_DGA_WORKAROUND
	int dotclock;
	XF86VidModeModeLine modeline;

	XF86VidModeGetModeLine(display, xf86ctx.screen, &dotclock, &modeline);
#endif

	if (!xf86ctx.modes)
	{
		xf86ctx.modes = XDGAQueryModes(display, xf86ctx.screen, &xf86ctx.mode_count);
		fprintf(stderr, "XDGA: info: found %d modes:\n", xf86ctx.mode_count);
	}

	/* also determine the max size of the display */
        sysdep_display_properties.max_width  = 0;
        sysdep_display_properties.max_height = 0;

	for(i=0;i<xf86ctx.mode_count;i++)
	{
#ifdef TDFX_DGA_WORKAROUND
          if ((xf86ctx.current_mode == -1) &&
                  xf86ctx.modes[i].viewportWidth == modeline.hdisplay &&
                  xf86ctx.modes[i].viewportHeight == modeline.vdisplay)
                  xf86ctx.current_X11_mode = xf86ctx.modes[i].num;
#endif
#if 0 /* DEBUG */
          fprintf(stderr, "XDGA: info: (%d) %s\n",
             xf86ctx.modes[i].num, xf86ctx.modes[i].name);
          fprintf(stderr, "          : VRefresh = %f [Hz]\n",
             xf86ctx.modes[i].verticalRefresh);
          /* flags */
          fprintf(stderr, "          : viewport = %dx%d\n",
             xf86ctx.modes[i].viewportWidth, xf86ctx.modes[i].viewportHeight);
          fprintf(stderr, "          : image = %dx%d\n",
             xf86ctx.modes[i].imageWidth, xf86ctx.modes[i].imageHeight);
          if (xf86ctx.modes[i].flags & XDGAPixmap)
                  fprintf(stderr, "          : pixmap = %dx%d\n",
                          xf86ctx.modes[i].pixmapWidth, xf86ctx.modes[i].pixmapHeight);
          fprintf(stderr, "          : bytes/scanline = %d\n",
             xf86ctx.modes[i].bytesPerScanline);
          fprintf(stderr, "          : byte order = %s\n",
                  xf86ctx.modes[i].byteOrder == MSBFirst ? "MSBFirst" :
                  xf86ctx.modes[i].byteOrder == LSBFirst ? "LSBFirst" :
                  "Unknown");
          fprintf(stderr, "          : bpp = %d, depth = %d\n",
                  xf86ctx.modes[i].bitsPerPixel, xf86ctx.modes[i].depth);
          fprintf(stderr, "          : RGBMask = (%lx, %lx, %lx)\n",
                  xf86ctx.modes[i].redMask,
                  xf86ctx.modes[i].greenMask,
                  xf86ctx.modes[i].blueMask);
          fprintf(stderr, "          : visual class = %s\n",
                  xf86ctx.modes[i].visualClass == TrueColor ? "TrueColor":
                  xf86ctx.modes[i].visualClass == DirectColor ? "DirectColor" :
                  xf86ctx.modes[i].visualClass == PseudoColor ? "PseudoColor" : "Unknown");
          fprintf(stderr, "          : xViewportStep = %d, yViewportStep = %d\n",
                  xf86ctx.modes[i].xViewportStep, xf86ctx.modes[i].yViewportStep);
          fprintf(stderr, "          : maxViewportX = %d, maxViewportY = %d\n",
                  xf86ctx.modes[i].maxViewportX, xf86ctx.modes[i].maxViewportY);
          /* viewportFlags */
#endif
          /* we only support TrueColor visuals */
          if(xf86ctx.modes[i].visualClass != TrueColor)
                  continue;
          
          score = mode_match(xf86ctx.modes[i].viewportWidth,
                  xf86ctx.modes[i].viewportHeight,
                  xf86ctx.modes[i].bytesPerScanline * 8 / 
                  xf86ctx.modes[i].bitsPerPixel,
                  xf86ctx.modes[i].depth,
                  xf86ctx.modes[i].bitsPerPixel);
          if(score > best_score)
          {
                  best_score = score;
                  bestmode   = xf86ctx.modes[i].num;
          }
	  /* also determine the max size of the display */
          if(xf86ctx.modes[i].viewportWidth > sysdep_display_properties.max_width)
            sysdep_display_properties.max_width = xf86ctx.modes[i].viewportWidth;
          if(xf86ctx.modes[i].viewportHeight > sysdep_display_properties.max_height)
            sysdep_display_properties.max_height = xf86ctx.modes[i].viewportHeight;
	}

	return bestmode;
}

static int xf86_dga_vidmode_setup_mode_restore(void)
{
	Display *disp;
	int status;
	pid_t pid;

	pid = fork();
	if(pid > 0)
	{
		waitpid(pid,&status,0);
		disp = XOpenDisplay(NULL);
		XDGACloseFramebuffer(disp, xf86ctx.screen);
		XDGASetMode(disp, xf86ctx.screen, 0);
		XCloseDisplay(disp);
		_exit(!WIFEXITED(status));
	}

	if (pid < 0)
	{
		perror("fork");
		return 1;
	}

	return 0;
}

static int xf86_dga_setup_graphics(XDGAMode modeinfo)
{
        int startx,starty,page,y;
	int scaled_height = sysdep_display_params.yarbsize?
	        sysdep_display_params.yarbsize:
	        sysdep_display_params.height*sysdep_display_params.heightscale;
        int scaled_width = ((sysdep_display_params.width+3)&~3) * 
                sysdep_display_params.widthscale;
	
        startx = ((modeinfo.viewportWidth - scaled_width) / 2) & ~3;
        starty = (modeinfo.viewportHeight - scaled_height) / 2;
	xf86ctx.addr  = xf86ctx.device->data;
	xf86ctx.addr += startx * modeinfo.bitsPerPixel / 8;
	xf86ctx.addr += starty * modeinfo.bytesPerScanline;

	/* clear the not used area of the display */
	for(page=0; page<=xf86ctx.max_page; page++)
	{
	  unsigned char *page_start = xf86ctx.device->data +
	       page * xf86ctx.aligned_viewport_height *
	       xf86ctx.device->mode.bytesPerScanline;
          
	  /* top */
	  memset(page_start, 0, starty*xf86ctx.device->mode.bytesPerScanline);
	  for(y=starty; y < (starty+scaled_height); y++)
	  {
	    /* left */
	    memset(page_start + y * xf86ctx.device->mode.bytesPerScanline, 0,
	       startx * modeinfo.bitsPerPixel / 8);
            /* right */
	    memset(page_start + (startx + scaled_width) * 
	       modeinfo.bitsPerPixel / 8 +
	       y * xf86ctx.device->mode.bytesPerScanline, 0,
	       (modeinfo.viewportWidth - (startx + scaled_width)) *
	       modeinfo.bitsPerPixel / 8);
	  }
	  /* bottom */
	  memset(page_start + (starty + scaled_height) *
	       xf86ctx.device->mode.bytesPerScanline, 0,
	       (modeinfo.viewportHeight - (starty + scaled_height)) *
	       xf86ctx.device->mode.bytesPerScanline);
	}

	/* reset old_dirty_area */
	memset(&xf86ctx.old_dirty_area, 0, sizeof(xf86ctx.old_dirty_area));
	
	return 0;
}

/* This name doesn't really cover this function, since it also sets up mouse
   and keyboard. This is done over here, since on most display targets the
   mouse and keyboard can't be setup before the display has. */
int xf86_dga2_open_display(int reopen)
{
	int i;
	/* only have todo the fork's the first time we go DGA, otherwise people
	   who do a lott of dga <-> window switching will get a lott of
	   children */
	static int first_time  = 1;
	xf86_dga_first_click   = 0;
	
        if (reopen)
        {
          sysdep_display_effect_close();
          return xf86_dga2_set_mode();
        }

	window  = RootWindow(display,xf86ctx.screen);
	
	if (first_time)
	{
		if(xf86_dga_vidmode_setup_mode_restore())
			return 1;
		first_time = 0;
	}

	/* HACK HACK HACK, keys get stuck when they are pressed when
	   XDGASetMode is called, so wait for all keys to be released */
	do {
	  char keys[32];
	  XQueryKeymap(display, keys);
	  for (i=0; (i<32) && (keys[i]==0); i++) {}
	} while(i<32);

        /* Grab keyb and mouse ! */
	if(xinput_open(1, 0))
	{
	    fprintf(stderr,"XGrabKeyboard failed\n");
	    return 1;
	}

	if(xf86_dga2_set_mode())
	    return 1;
	    
	/* setup the colormap */
	xf86ctx.cmap = XDGACreateColormap(display, xf86ctx.screen,
					  xf86ctx.device, AllocNone);
	XDGAInstallColormap(display,xf86ctx.screen,xf86ctx.cmap);
	
	return 0;
}

static int xf86_dga2_set_mode(void)
{
	int bestmode = xf86_dga_vidmode_find_best_vidmode();
	
	if (bestmode == -1)
	{
		fprintf(stderr,"no suitable mode found\n");
		return 1;
	}
	if (bestmode != xf86ctx.current_mode)
	{

          if(xf86ctx.device)
                  XFree(xf86ctx.device);

          xf86ctx.device = XDGASetMode(display,xf86ctx.screen,bestmode);
          if (xf86ctx.device == NULL) {
                  fprintf(stderr,"XDGASetMode failed\n");
                  return 1;
          }
          xf86ctx.width = xf86ctx.device->mode.bytesPerScanline * 8 / 
                  xf86ctx.device->mode.bitsPerPixel;
          xf86ctx.current_mode = bestmode;

  #if 0 /* DEBUG */
          fprintf(stderr, "Debug: bitmap_depth =%d   mode.bitsPerPixel = %d"
                          "   mode.depth = %d\n", bitmap_depth, 
                          xf86ctx.device->mode.bitsPerPixel, 
                          xf86ctx.device->mode.depth);
  #endif

          fprintf(stderr,"XF86DGA2 switched To Mode: %d x %d\n",
                  xf86ctx.device->mode.viewportWidth,
                  xf86ctx.device->mode.viewportHeight);

          mode_set_aspect_ratio((double)xf86ctx.device->mode.viewportWidth/
                  xf86ctx.device->mode.viewportHeight);

          /* setup the viewport */
          XDGASetViewport(display,xf86ctx.screen,0,0,0);
          while(XDGAGetViewportStatus(display, xf86ctx.screen))
                  ;

          /* setup page flipping */
          if(xf86ctx.device->mode.viewportFlags & XDGAFlipRetrace)
          {
            xf86ctx.aligned_viewport_height =
              (xf86ctx.device->mode.viewportHeight+
               xf86ctx.device->mode.yViewportStep-1) &
              ~(xf86ctx.device->mode.yViewportStep-1);
            xf86ctx.page = 0;
            xf86ctx.max_page = xf86ctx.device->mode.maxViewportY /
              xf86ctx.aligned_viewport_height;
            if (xf86ctx.max_page > xf86ctx.max_page_limit)
              xf86ctx.max_page = xf86ctx.max_page_limit;
            if (xf86ctx.max_page)
              fprintf(stderr,
                "DGA using vsynced page flipping, hw-buffering max %d frames\n",
                xf86ctx.max_page);
          }
          else
            xf86ctx.max_page = 0;
            
          /* fill the sysdep_display_properties struct */
          memset(&sysdep_display_properties.palette_info, 0, sizeof(struct
            sysdep_palette_info));
          sysdep_display_properties.palette_info.red_mask   = xf86ctx.device->mode.redMask;
          sysdep_display_properties.palette_info.green_mask = xf86ctx.device->mode.greenMask;
          sysdep_display_properties.palette_info.blue_mask  = xf86ctx.device->mode.blueMask;
          sysdep_display_properties.palette_info.depth = xf86ctx.device->mode.depth;
          sysdep_display_properties.palette_info.bpp   = xf86ctx.device->mode.bitsPerPixel;
	  sysdep_display_properties.vector_renderer    = NULL;
	}
	
        if(xf86_dga_setup_graphics(xf86ctx.device->mode))
          return 1;

        /* get a blit function */
        return !(xf86ctx.update_display_func=sysdep_display_effect_open());
}

const char *xf86_dga2_update_display(mame_bitmap *bitmap,
	  rectangle *vis_area, rectangle *dirty_area,
	  struct sysdep_palette_struct *palette, int flags)
{
  rectangle my_dirty_area = *dirty_area;
  
  if (xf86ctx.max_page)
  {
    /* force a full screen update */
    if (xf86ctx.page_dirty)
    {
      my_dirty_area = *vis_area;
      xf86ctx.page_dirty--;
    }
    while(XDGAGetViewportStatus(display, xf86ctx.screen) & (0x01 <<
          (xf86ctx.max_page - 1)))
    {
    }
  }

  xf86ctx.page = (xf86ctx.page + 1) % (xf86ctx.max_page + 1);
  xf86ctx.update_display_func(bitmap, vis_area, &my_dirty_area,
        palette, xf86ctx.addr + xf86ctx.aligned_viewport_height *
	xf86ctx.page * xf86ctx.device->mode.bytesPerScanline, xf86ctx.width);

  if (xf86ctx.max_page)
  {
    XDGASetViewport(display, xf86ctx. screen, 0, xf86ctx.page *
      xf86ctx.aligned_viewport_height, XDGAFlipRetrace);

    /* If the dirty area has changed force a fullscreen update the next
       max_page updates, so that it gets updated in all pages */
    if (memcmp(&xf86ctx.old_dirty_area, dirty_area, sizeof(xf86ctx.old_dirty_area)))
    {
      xf86ctx.old_dirty_area = *dirty_area;
      xf86ctx.page_dirty = xf86ctx.max_page;
    }
  }

  XDGASync(display,xf86ctx.screen);
  
  return NULL;
}

void xf86_dga2_clear_display(void)
{
  int page,y;
  int scaled_height = sysdep_display_params.yarbsize?
          sysdep_display_params.yarbsize:
          sysdep_display_params.height*sysdep_display_params.heightscale;
  int scaled_width = ((sysdep_display_params.width+3)&~3) * 
          sysdep_display_params.widthscale;

  for(page=0; page<=xf86ctx.max_page; page++)
  {
    for(y=0; y<scaled_height; y++)
      memset(xf86ctx.addr + (xf86ctx.aligned_viewport_height * page + y) *
        xf86ctx.device->mode.bytesPerScanline, 0,
        scaled_width * xf86ctx.device->mode.bitsPerPixel / 8);
  }
}

void xf86_dga2_close_display(void)
{
	if(xf86ctx.device)
	{
		XFree(xf86ctx.device);
		xf86ctx.device = 0;
	}
	if(xf86ctx.modes)
	{
		XFree(xf86ctx.modes);
		xf86ctx.modes = 0;
	}
	if(xf86ctx.cmap)
	{
		XFreeColormap(display,xf86ctx.cmap);
		xf86ctx.cmap = 0;
	}
        sysdep_display_effect_close();
	xinput_close();
	if(xf86ctx.current_mode != -1)
	{
		/* HDG: is this really nescesarry ? */
		XDGASync(display,xf86ctx.screen);
#ifdef TDFX_DGA_WORKAROUND
		/* Restore the right video mode before leaving DGA  */
		/* The tdfx driver would have to do it, but it doesn't work ...*/
		XDGASetMode(display, xf86ctx.screen, xf86ctx.current_X11_mode);
#endif
		XDGASetMode(display, xf86ctx.screen, 0);
		xf86ctx.current_mode = -1;
	}
	XSync(display, True);
}

#endif /*def X_XDGASetMode*/
