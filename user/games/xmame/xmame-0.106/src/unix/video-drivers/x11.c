/*
 * X-Mame video specifics code
 *
 */
#ifdef x11
#define __X11_C_

/*
 * Include files.
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#ifdef HAVE_XINERAMA
#include <X11/extensions/Xinerama.h>
#endif

/* for xscreensaver support */
/* Commented out for now since it causes problems with some 
 * versions of KDE. */
/* #include "vroot.h" */

#include "sysdep/sysdep_display_priv.h"
#include "x11.h"

static char *x11_geometry;
#ifdef HAVE_XINERAMA
static int xinerama_screen;
#endif

static int x11_parse_geom(struct rc_option *option, const char *arg, int priority);
static void x11_get_geometry(int *x, int *y, unsigned int *width,
  unsigned int *height, int *win_gravity, long *flags, int type);

struct rc_option sysdep_display_opts[] = {
	/* name, shortname, type, dest, deflt, min, max, func, help */
   	{ NULL, NULL, rc_link, aspect_opts, NULL, 0, 0, NULL, NULL },
	{ "X11 Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
	{ "geometry", "geo", rc_string, &x11_geometry, "", 0, 0, x11_parse_geom, "Specify the size (if resizable) and location of the window" },
	{ "xsync", "xs", rc_bool, &use_xsync, "1", 0, 0, NULL, "Use/don't use XSync instead of XFlush as screen refresh method" },
	{ "root_window_id", "rid", rc_int, &root_window_id, "0", 0, 0, NULL, "Create the xmame window in an alternate root window; mostly useful for front-ends!" },
	{ "run-in-root-window", "root", rc_bool, &run_in_root_window, "0", 0, 0, NULL, "Enable/disable running in root window" },
#ifdef HAVE_XINERAMA
	{ "xinerama-screen", NULL, rc_int, &xinerama_screen, "0", 0, 0, NULL,
	  "Select Xinerama screen for fullscreen, use -1 to stretch over all monitors" },
#endif
	{ NULL, NULL, rc_link, x11_window_opts, NULL, 0, 0, NULL, NULL },
#ifdef USE_DGA
	{ NULL, NULL, rc_link, xf86_dga_opts, NULL, 0, 0, NULL, NULL },
#endif
#ifdef USE_XV
	{ NULL, NULL, rc_link, xv_opts, NULL, 0, 0, NULL, NULL },
#endif
#ifdef USE_OPENGL
	{ NULL, NULL, rc_link, xgl_opts, NULL, 0, 0, NULL, NULL },
#endif
#ifdef USE_GLIDE
	{ NULL, NULL, rc_link, fx_opts, NULL, 0, 0, NULL, NULL },
#endif
#ifdef USE_XIL
	{ NULL, NULL, rc_link, xil_opts, NULL, 0, 0, NULL, NULL },
#endif
	{ NULL, NULL, rc_link, x11_input_opts, NULL, 0, 0, NULL, NULL },
	{ NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

struct x_func_struct {
	int  (*init)(void);
	int  (*open_display)(int reopen);
	void (*close_display)(void);
	const char * (*update_display)(mame_bitmap *bitmap,
	  rectangle *src_bounds,  rectangle *dest_bounds,
	  struct sysdep_palette_struct *palette, int flags);
        void (*clear_display_buffer)(void);
        void (*exit)(void);
};

/* HACK - HACK - HACK for fullscreen */
#define MWM_HINTS_DECORATIONS   2
typedef struct {
	long flags;
	long functions;
	long decorations;
	long input_mode;
} MotifWmHints;

static struct x_func_struct x_func[] = {
{ x11_window_init,
  x11_window_open_display,
  x11_window_close_display,
  x11_window_update_display,
  x11_window_clear_display_buffer,
  NULL },
#ifdef USE_XV
{ xv_init,
  xv_open_display,
  xv_close_display,
  xv_update_display,
  xv_clear_display_buffer,
  NULL },
#else
{ NULL, NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef USE_OPENGL
{ xgl_init,
  xgl_open_display,
  xgl_close_display,
  xgl_update_display,
  NULL,
  NULL },
#else
{ NULL, NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef USE_GLIDE
{ xfx_init,
  xfx_open_display,
  xfx_close_display,
  xfx_update_display,
  NULL,
  xfx_exit },
#else
{ NULL, NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef USE_XIL
{ xil_init,
  xil_open_display,
  xil_close_display,
  xil_update_display,
  xil_clear_display_buffer,
  NULL },
#else
{ NULL, NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef USE_DGA
{ xf86_dga_init,
  xf86_dga_open_display,
  xf86_dga_close_display,
  xf86_dga_update_display,
  xf86_dga_clear_display,
  NULL }
#else
{ NULL, NULL, NULL, NULL, NULL, NULL }
#endif
};

static const char *x11_mode_name[] = {
  "Normal",
  "XVideo",
  "OpenGL",
  "Glide",
  "XIL"
};

static int x11_parse_geom(struct rc_option *option, const char *arg, int priority)
{
  if (strlen(x11_geometry))
  {
    int i = XParseGeometry(x11_geometry, &i, &i, &custom_window_width,
      &custom_window_height);
    if (!(i & WidthValue))
      custom_window_width = 0;
    if (!(i & HeightValue))
      custom_window_height = 0;
    if (!(i & (XValue|YValue|WidthValue|HeightValue)))
    {
      fprintf(stderr,"Invalid geometry: %s.\n", arg);
      return 1;
    }
  }
  else
    custom_window_width = custom_window_height = 0;

  return 0;
}

int sysdep_display_init (void)
{
	int i;

	window = 0;

	memset(sysdep_display_properties.mode_info, 0,
	  SYSDEP_DISPLAY_VIDEO_MODES * sizeof(int));
        /* to satisfy checking for a valid video_mode for
           handling -help, etc without a display. */
        sysdep_display_properties.mode_info[X11_WINDOW] =
          SYSDEP_DISPLAY_WINDOWED|SYSDEP_DISPLAY_EFFECTS;
        /* fill in the mode names */
        memcpy(sysdep_display_properties.mode_name, x11_mode_name,
          SYSDEP_DISPLAY_VIDEO_MODES * sizeof(const char *));
        
	if(!(display = XOpenDisplay (NULL)))
	{
		/* don't make this a fatal error so that cmdline options
		   like -help will still work. Also don't report this
		   here to not polute the -help output */
		return 0;
	}
	screen=DefaultScreenOfDisplay(display);

	for (i=0;i<SYSDEP_DISPLAY_VIDEO_MODES;i++)
	{
		if(x_func[i].init)
			sysdep_display_properties.mode_info[i] = x_func[i].init();
		else
			sysdep_display_properties.mode_info[i] = 0;
	}

	if (x_func[X11_DGA].init)
          sysdep_display_properties.mode_info[X11_WINDOW] |= x_func[X11_DGA].init();

	return 0;
}

void sysdep_display_exit(void)
{
        int i;
        
	if(display)
	{
                for (i=0;i<=X11_DGA;i++)
                        if(x_func[i].exit)
                                x_func[i].exit();

		XCloseDisplay (display);
        }
}

/* This name doesn't really cover this function, since it also sets up mouse
   and keyboard. This is done over here, since on most display targets the
   mouse and keyboard can't be setup before the display has. */
int sysdep_display_driver_open(int reopen)
{
  int mode = sysdep_display_params.video_mode;
  
  if (!display)
  {
    fprintf (stderr, "Error: could not open display\n");
    return 1;
  }
  
  if ((sysdep_display_params.video_mode == X11_WINDOW) &&
      sysdep_display_params.fullscreen)
  {
    mode = X11_DGA;
    sysdep_display_properties.mode_name[X11_WINDOW]  = "DGA";
    sysdep_display_properties.mode_info[X11_WINDOW] |=
      SYSDEP_DISPLAY_DIRECT_FB;
  }
  
  /* force a full update the next update */
  x11_exposed = 1;

  return x_func[mode].open_display(reopen);
}

void sysdep_display_close(void)
{
  int mode = ((sysdep_display_params.video_mode == X11_WINDOW) &&
    sysdep_display_params.fullscreen)? X11_DGA:
    sysdep_display_params.video_mode;
  
  if (display)
    (*x_func[mode].close_display)();
    
  /* restore default mode settings for X11_WINDOW mode */
  sysdep_display_properties.mode_name[X11_WINDOW] = 
    x11_mode_name[X11_WINDOW];
  sysdep_display_properties.mode_info[X11_WINDOW] &=
    ~SYSDEP_DISPLAY_DIRECT_FB;
}

const char *sysdep_display_update(mame_bitmap *bitmap,
  rectangle *vis_area, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, int keyb_leds, int flags)
{
        int mode = ((sysdep_display_params.video_mode == X11_WINDOW) &&
          sysdep_display_params.fullscreen)? X11_DGA:
          sysdep_display_params.video_mode;
        
	/* do we need todo a full update? */
	if(x11_exposed)
	{
	 	*dirty_area = *vis_area;
	 	x11_exposed = 0;
	}
   
	xinput_update(keyb_leds, flags);
	
	return x_func[mode].update_display(
	  bitmap, vis_area, dirty_area, palette, flags);
}

void sysdep_display_driver_clear_buffer(void)
{
  int mode = ((sysdep_display_params.video_mode == X11_WINDOW) &&
    sysdep_display_params.fullscreen)? X11_DGA:
    sysdep_display_params.video_mode;
  
  x_func[mode].clear_display_buffer();
}

int x11_init_palette_info(void)
{
	if (screen->root_visual->class != TrueColor)
	{
		fprintf(stderr, "X11-Error: only TrueColor visuals are supported\n");
		return 1;
	}

	/* fill the sysdep_display_properties struct */
	memset(&sysdep_display_properties.palette_info, 0, sizeof(struct
	  sysdep_palette_info));
	sysdep_display_properties.palette_info.red_mask      = screen->root_visual->red_mask;
	sysdep_display_properties.palette_info.green_mask    = screen->root_visual->green_mask;
	sysdep_display_properties.palette_info.blue_mask     = screen->root_visual->blue_mask;
	sysdep_display_properties.palette_info.depth         = screen->root_depth;
	sysdep_display_properties.vector_renderer            = NULL;

	return 0;
}

void x11_resize_window(unsigned int *width, unsigned int *height,
  int type)
{
  Window _dw;
  int _dint;
  unsigned int _duint, window_width, window_height;
  
  x11_get_geometry(&_dint, &_dint, width, height, &_dint, NULL, type);
  XGetGeometry(display, window, &_dw, &_dint, &_dint, &window_width,
    &window_height, &_duint, &_duint);
    
  if ((*width != window_width) || (*height != window_height))
  {
    if (type != X11_RESIZABLE)
      x11_set_window_hints(X11_RESIZABLE);
    XResizeWindow(display, window, *width, *height);
    if (type != X11_RESIZABLE)
      x11_set_window_hints(type);
  }
}

/* Create a window, type can be:
   0: Fixed size of width and height
   1: Resizable, if custom_width and -height are set then width and height are
      set to these, else they are determined from sysdep_display_params. The
      aspect is kept to sysdep_display_params.aspect.
   2: Same as 1, but without any aspect constrains.
   
   Notes:
   1) If run_in_root_window is set then type gets ignored, and
      the width and height of/and the root window are returned. (Else ...)
   2) If sysdep_display_params.fullscreen is set a fullscreen window is
      created. (Else ...)
   3) If root_window_id is set it is used as the parent window instead of
      the root window. */
int x11_create_window(unsigned int *width, unsigned int *height, int type)
{
	XSetWindowAttributes winattr;
	unsigned long winattrmask;
	XEvent event;
	int x,y;
	Window root = RootWindowOfScreen (screen);

	x11_get_geometry(&x, &y, width, height, &winattr.win_gravity,
			NULL, type);

	if (run_in_root_window)
	{
		window = root;
		return 0;
	}

	if (!sysdep_display_params.fullscreen && root_window_id)
		root = root_window_id;

	/* Create and setup the window. No buttons, no fancy stuff. */
	winattr.background_pixel  = BlackPixelOfScreen (screen);
	winattr.border_pixel      = WhitePixelOfScreen (screen);
	winattr.bit_gravity       = ForgetGravity;
	winattr.backing_store     = NotUseful;
	winattr.override_redirect = False;
	winattr.save_under        = False;
	winattr.event_mask        = 0;
	winattr.do_not_propagate_mask = 0;
	winattr.colormap          = DefaultColormapOfScreen (screen);
	winattr.cursor            = None;

	winattrmask = CWBorderPixel | CWBackPixel | CWBitGravity | CWWinGravity | 
			CWBackingStore | CWOverrideRedirect | CWSaveUnder | CWEventMask | 
			CWDontPropagate | CWColormap | CWCursor;

	window = XCreateWindow(display, root, x, y, *width, *height, 0,
			screen->root_depth, InputOutput, screen->root_visual,
			winattrmask, &winattr);
	if (!window)
	{
		fprintf (stderr, "OSD ERROR: failed in XCreateWindow().\n");
		return 1;
	}

	/* set the hints */
	x11_set_window_hints(type);

	XSelectInput (display, window, ExposureMask);
	XMapRaised   (display, window);
	XClearWindow (display, window);
	XWindowEvent (display, window, ExposureMask, &event);

	return 0;
}

/* Set the hints for a window, window-type can be:
   0: Fixed size
   1: Resizable, aspect is always kept to sysdep_display_params.aspect .
   2: Resizable */
void x11_set_window_hints(int type)
{
        struct rc_option *option;
        XWMHints wm_hints;
	XSizeHints hints;
	XClassHint class_hints = { NAME, NAME };
	XTextProperty window_name, icon_name;
	XTextProperty *window_name_p = &window_name;
	XTextProperty *icon_name_p = &icon_name;
	unsigned int width, height;
	char *app = NAME;

        x11_get_geometry(&hints.x, &hints.y, &width, &height,
	          &hints.win_gravity, &hints.flags, type);

        if (run_in_root_window)
          return;
        
	/* WM hints */
        wm_hints.input   = True;
        wm_hints.flags   = InputHint;

	/* Size hints */
	if (!sysdep_display_params.fullscreen)
	  switch (type)
	  {
	    case X11_FIXED: /* fixed size */
		hints.flags |= PSize | PMinSize | PMaxSize;
		break;
	    case X11_RESIZABLE_ASPECT: /* resizable, keep aspect */
	    	/* detect -keepaspect */
	        option = rc_get_option2(aspect_opts, "keepaspect");
	    	if (option && *((int *)option->dest))
	    	{
                  unsigned int x = 1024;
                  unsigned int y = 1024;

	    	  mode_clip_aspect(x, y, &x, &y);

	    	  hints.min_aspect.x = x;
	    	  hints.min_aspect.y = y;
	    	  hints.max_aspect.x = x;
	    	  hints.max_aspect.y = y;
		  hints.flags |= PAspect;
		}
	    case X11_RESIZABLE: /* resizable */
		hints.flags |= PSize;
		break;
	  }
        
	hints.min_width  = hints.max_width  = hints.base_width  = width;
	hints.min_height = hints.max_height = hints.base_height = height;
        
        /* Hack to get rid of window title bar */
        if(sysdep_display_params.fullscreen)
        {
                Atom mwmatom;
                MotifWmHints mwmhints;
                mwmhints.flags=MWM_HINTS_DECORATIONS;
                mwmhints.decorations=0;
                mwmatom=XInternAtom(display,"_MOTIF_WM_HINTS",0);

                XChangeProperty(display,window,mwmatom,mwmatom,32,
                                PropModeReplace,(unsigned char *)&mwmhints,4);
        }

	if (!XStringListToTextProperty(&app, 1, &window_name)) {
		fprintf(stderr, "Warning: Structure allocation for window_name failed\n");
		window_name_p = NULL;
	}

	if (!XStringListToTextProperty(&app, 1, &icon_name)) {
		fprintf( stderr, "Warning: Structure allocation for icon_name failed\n" );
		icon_name_p = NULL;
	}

	XSetWMProperties(display, window, window_name_p, icon_name_p,
	    NULL, 0, &hints, &wm_hints, &class_hints);

        XStoreName (display, window, sysdep_display_params.title);
        
        if (window_name_p)
          XFree(window_name_p->value);
        if (icon_name_p)
          XFree(icon_name_p->value);
}

static void x11_get_geometry(int *x, int *y, unsigned int *width,
  unsigned int *height, int *win_gravity, long *flags, int type)
{
  /* set aspect_ratio, do this early since this can change yarbsize */
  mode_set_aspect_ratio((double)screen->width/screen->height);

  if (run_in_root_window)
  {
    *x = 0;
    *y = 0;
    *width  = screen->width;
    *height = screen->height;
    *win_gravity = NorthWestGravity;
    if (flags)
      *flags = 0;
    sysdep_display_params.fullscreen = 0;
  }
  else if (sysdep_display_params.fullscreen)
  {
    /*
     * Get the window size and location for a fullscreen display.  Normally
     *  this is simply the default screen coordinates.  When using Xinerama
     *  different heads may have different capabilities.  This function
     *  will attempt to honor the xinerama-screen parameter and use only
     *  a specific head for fullscreen output.
     */
#ifdef HAVE_XINERAMA
    XineramaScreenInfo *xinerama_screens = NULL;
    int number_screens;
#endif /* HAVE_XINERAMA */

    /* initialize the results to default values */
    *x = 0;
    *y = 0;
    *width  = screen->width;
    *height = screen->height;
    *win_gravity = NorthWestGravity;
    if (flags)
      *flags = PMinSize|PMaxSize|USPosition|USSize;

#ifdef HAVE_XINERAMA
    if (!XineramaIsActive(display) || xinerama_screen < 0) {
            /* nothing more to do */
            return;
    }

    xinerama_screens = XineramaQueryScreens(display, &number_screens);
    if (xinerama_screens == NULL) {
            /* error -- return with the defaults */
            return;
    }

    /* check that the user selected screen is valid */
    if (xinerama_screen >= 0 && xinerama_screen < number_screens) {
            *x = xinerama_screens[xinerama_screen].x_org;
            *y = xinerama_screens[xinerama_screen].y_org;
            *width = xinerama_screens[xinerama_screen].width;
            *height = xinerama_screens[xinerama_screen].height;
    }

    XFree(xinerama_screens);
#endif /* HAVE_XINERAMA */
  }
  else
  {
    int i;
    XSizeHints hints;
    
    if (type == X11_FIXED)
    {
      *width  = sysdep_display_params.width * 
        sysdep_display_params.widthscale;
      *height = sysdep_display_params.yarbsize?
        sysdep_display_params.yarbsize:
        sysdep_display_params.height * sysdep_display_params.heightscale;
    }
    else
    {
      struct rc_option *option;

      if (custom_window_width)
      {
        *width  = custom_window_width;
        *height = custom_window_height;
      }
      else
      {
        *width  = sysdep_display_params.max_width *
          sysdep_display_params.widthscale;
        *height = sysdep_display_params.yarbsize?
          sysdep_display_params.yarbsize:
          sysdep_display_params.max_height *
            sysdep_display_params.heightscale;
      }

      /* detect -keepaspect */
      option = rc_get_option2(aspect_opts, "keepaspect");
      if ((type == X11_RESIZABLE_ASPECT) && option && *((int *)option->dest))
      {
        if (custom_window_width)
          mode_clip_aspect(*width, *height, width, height);
        else
          mode_stretch_aspect(*width, *height, width, height);
      }
    }
    
    hints.min_width  = hints.max_width  = hints.base_width  = *width;
    hints.min_height = hints.max_height = hints.base_height = *height;
    hints.flags      = PSize | PMinSize | PMaxSize;
    
    i = XWMGeometry(display, DefaultScreen(display), x11_geometry, "+0+0", 0,
      &hints, x, y, &i, &i, win_gravity);

    if (flags)
    {
      if (i & (XValue|YValue))
        *flags = PPosition | PWinGravity;
      else
        *flags = 0;
    }
  }
}

#endif /* ifdef x11 */
