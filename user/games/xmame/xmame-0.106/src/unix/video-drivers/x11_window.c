/*
 * Modifications For OpenVMS By:  Robert Alan Byer
 *                                byer@mail.ourservers.net
 *                                Jan. 9, 2004
 */
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#ifdef USE_MITSHM
#  if defined(__DECC) && defined(VMS)
#    include <X11/extensions/ipc.h>
#    include <X11/extensions/shm.h>
#  else
#    include <sys/ipc.h>
#    include <sys/shm.h>
#  endif
#  include <X11/extensions/XShm.h>
#endif

#include "sysdep/sysdep_display_priv.h"
#include "x11.h"

static blit_func_p x11_window_update_display_func;

/* we need these to do the clean up correctly */
#ifdef USE_MITSHM
static int mit_shm_available = 0;
static int mit_shm_attached  = 0;
static XShmSegmentInfo shm_info;
static int use_mit_shm;
#endif

static XImage *image = NULL;
static GC gc;
enum { X11_NORMAL, X11_MITSHM };
static int x11_window_update_method;
static int startx = 0;
static int starty = 0;

struct rc_option x11_window_opts[] = {
        /* name, shortname, type, dest, deflt, min, max, func, help */
        { "X11-window Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL,  NULL },
#ifdef USE_MITSHM
        { "mitshm", "ms", rc_bool, &use_mit_shm, "1", 0, 0, NULL, "Use/don't use MIT Shared Mem (if available and compiled in)" },
#endif
        { NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

static void x11_window_destroy_image(void);

/*
 * Create a display screen, or window, large enough to accomodate a bitmap
 * of the given dimensions.
 */

#ifdef USE_MITSHM
/* following routine traps missused MIT-SHM if not available */
int x11_test_mit_shm (Display * display, XErrorEvent * error)
{
        char msg[256];
        unsigned char ret = error->error_code;

        /* if MIT-SHM request failed, note and continue */
        if ((ret == BadAccess) || (ret == BadAlloc))
        {
                x11_mit_shm_error = 1;
                return 0;
        }
        /* else unexpected error code: notify and exit */
        XGetErrorText (display, ret, msg, 256);
        fprintf (stderr, "Unexpected X Error %d: %s\n", (int)ret, msg);
        exit(1);
        /* to make newer gcc's shut up, grrr */
        return 0;
}
#endif

int x11_window_init(void)
{ 
  int i;
#ifdef USE_MITSHM
  shm_info.shmaddr = NULL;
  /* get XExtensions to see if mit shared memory is available */
  if (XQueryExtension (display, "MIT-SHM", &i, &i, &i))
    mit_shm_available = 1;
  else
    fprintf (stderr, "X-Server Doesn't support MIT-SHM extension\n");
#endif
  return SYSDEP_DISPLAY_WINDOWED|SYSDEP_DISPLAY_EFFECTS;
}

/* This name doesn't really cover this function, since it also sets up mouse
   and keyboard. This is done over here, since on most display targets the
   mouse and keyboard can't be setup before the display has. */
int x11_window_open_display(int reopen)
{
        int needed_width, needed_height;

        /* set aspect_ratio, do this early since this can change yarbsize */
        mode_set_aspect_ratio((double)screen->width/screen->height);

        needed_width  = sysdep_display_params.width * 
          sysdep_display_params.widthscale;
        needed_height = sysdep_display_params.yarbsize?
          sysdep_display_params.yarbsize:
          sysdep_display_params.height * sysdep_display_params.heightscale;

        if(!reopen)
        {
          XGCValues xgcv;
          /* setup the sysdep_display_properties struct */
          sysdep_display_properties.max_width  = -1;
          sysdep_display_properties.max_height = -1;
          if (x11_init_palette_info())
                  return 1;

          /* create a window */
          if (x11_create_window(&window_width, &window_height, X11_FIXED))
            return 1;

          if ((needed_width > window_width) || (needed_height > window_height))
          {
            fprintf (stderr, "OSD ERROR: Window is to small: %dx%d, needed %dx%d\n",
              needed_width, needed_height, window_width, window_height);
            return 1;
          }

          startx = ((window_width  - needed_width)  / 2) & ~3;
          starty = ((window_height - window_height) / 2) & ~3;

          /* create gc */
          gc = XCreateGC (display, window, 0, &xgcv);

	  /* open xinput */
          xinput_open(0, ExposureMask);
        }
        else
        {
          sysdep_display_effect_close();
          
          if ( (needed_width  > image->width)  ||
               (needed_height > image->height) )
            x11_window_destroy_image();
          
          x11_resize_window(&window_width, &window_height, X11_FIXED);
        }

        /* create and setup the image */
        if (!image)
        {
          char *scaled_buffer_ptr;
          int image_width  = sysdep_display_params.widthscale *
            sysdep_display_params.max_width;
          int image_height = sysdep_display_params.yarbsize?
            sysdep_display_params.yarbsize:
            sysdep_display_params.max_height * sysdep_display_params.heightscale;

#ifdef USE_MITSHM        
          if (mit_shm_available && use_mit_shm)
            x11_window_update_method = X11_MITSHM;
          else
#endif
            x11_window_update_method = X11_NORMAL;

          switch (x11_window_update_method)
          {
#ifdef USE_MITSHM
                case X11_MITSHM:
                        /* Create a MITSHM image. */
                        fprintf (stderr, "MIT-SHM Extension Available. trying to use... ");
                        x11_mit_shm_error = 0;
                        XSetErrorHandler (x11_test_mit_shm);
                        image = XShmCreateImage (display,
                                        screen->root_visual,
                                        screen->root_depth,
                                        ZPixmap,
                                        NULL,
                                        &shm_info,
                                        image_width,
                                        image_height);
                        if (image)
                        {
                                shm_info.readOnly = False;
                                shm_info.shmid = shmget (IPC_PRIVATE,
                                                image->bytes_per_line * image->height,
                                                (IPC_CREAT | 0777));
                                if (shm_info.shmid < 0)
                                {
                                        fprintf (stderr, "\nError: failed to create MITSHM block.\n");
                                        return 1;
                                }

                                /* And allocate the bitmap buffer. */
                                image->data = shm_info.shmaddr =
                                        (char *) shmat (shm_info.shmid, 0, 0);
                                if (!image->data)
                                {
                                        fprintf (stderr, "\nError: failed to allocate MITSHM bitmap buffer.\n");
                                        return 1;
                                }

                                /* Attach the MITSHM block. this will cause an exception if */
                                /* MIT-SHM is not available. so trap it and process         */
                                if (!XShmAttach (display, &shm_info))
                                {
                                        fprintf (stderr, "\nError: failed to attach MITSHM block.\n");
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

                                if (!x11_mit_shm_error)
                                {
                                        fprintf (stderr, "Success.\nUsing Shared Memory Features to speed up\n");
                                        XSetErrorHandler (None);  /* Restore error handler to default */
                                        mit_shm_attached = 1;
                                        break;
                                }
                                /* else we have failed clean up before retrying without MITSHM */
                                shmdt (shm_info.shmaddr);
                                shm_info.shmaddr = NULL;
                                XDestroyImage (image);
                                image = NULL;
                        }
                        XSetErrorHandler (None);  /* Restore error handler to default */
                        fprintf (stderr, "Failed\nReverting to normal XPutImage() mode\n");
                        x11_window_update_method = X11_NORMAL;
#endif
                case X11_NORMAL:
                        scaled_buffer_ptr=malloc(((screen->root_depth <= 16)?
                          2:4) * image_width * image_height);
                        if (!scaled_buffer_ptr)
                        {
                                fprintf (stderr, "Error: failed to allocate bitmap buffer.\n");
                                return 1;
                        }
                        image = XCreateImage (display,
                                        screen->root_visual,
                                        screen->root_depth,
                                        ZPixmap,
                                        0,
                                        scaled_buffer_ptr,
                                        image_width, image_height,
                                        32, /* image_width always is a multiple of 4 */
                                        0);

                        if (!image)
                        {
                                free (scaled_buffer_ptr);
                                fprintf (stderr, "OSD ERROR: could not create image.\n");
                                return 1;
                        }
                        break;
                default:
                        fprintf (stderr, "Error unknown X11 update method, this shouldn't happen\n");
                        return 1;
          }
          sysdep_display_properties.palette_info.bpp = image->bits_per_pixel;
        }

        /* get a blit function */
        return !(x11_window_update_display_func=sysdep_display_effect_open());
}

/*
 * Shut down the display, also called by the core to clean up if any error
 * happens when creating the display.
 */
void x11_window_close_display (void)
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
   x11_window_destroy_image();
   
   XSync (display, True); /* send all events to sync; discard events */
}

static void x11_window_destroy_image(void)
{
#ifdef USE_MITSHM
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
#endif
   if (image)
   {
       XDestroyImage (image);
       image = NULL;
   }
}

/* invoked by main tree code to update bitmap into screen */
const char *x11_window_update_display(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, int flags)
{
   x11_window_update_display_func(bitmap, vis_in_dest_out, dirty_area,
     palette, (unsigned char *)image->data, image->width);
   
   switch (x11_window_update_method)
   {
      case X11_MITSHM:
#ifdef USE_MITSHM
         XShmPutImage (display, window, gc, image,
           vis_in_dest_out->min_x, vis_in_dest_out->min_y,
           startx+vis_in_dest_out->min_x, starty+vis_in_dest_out->min_y,
           vis_in_dest_out->max_x - vis_in_dest_out->min_x,
           vis_in_dest_out->max_y - vis_in_dest_out->min_y, False);
#endif
         break;
      case X11_NORMAL:
         XPutImage (display, window, gc, image,
           vis_in_dest_out->min_x, vis_in_dest_out->min_y,
           startx+vis_in_dest_out->min_x, starty+vis_in_dest_out->min_y,
           vis_in_dest_out->max_x - vis_in_dest_out->min_x,
           vis_in_dest_out->max_y - vis_in_dest_out->min_y);
         break;
   }

   /* some games "flickers" with XFlush, so command line option is provided */
   if (use_xsync)
      XSync (display, False);   /* be sure to get request processed */
   else
      XFlush (display);         /* flush buffer to server */
      
   return NULL;
}

void x11_window_clear_display_buffer(void)
{
   memset(image->data, 0, image->width*image->height*image->bits_per_pixel/8);
}
