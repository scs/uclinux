/***************************************************************************
                                          
 This is the SDL XMAME display driver.
 FIrst incarnation by Tadeusz Szczyrba <trevor@pik-nel.pl>,
 based on the Linux SVGALib adaptation by Phillip Ezolt.

 Rewritten for the new video code by Hans de Goede,
 the text below is from before this reorganisation and in many
 ways no longer accurate!

 updated and patched by Ricardo Calixto Quesada (riq@core-sdi.com)

 patched by Patrice Mandin (pmandin@caramail.com)
  modified support for fullscreen modes using SDL and XFree 4
  added toggle fullscreen/windowed mode (Alt + Return)
  added title for the window
  hide mouse cursor in fullscreen mode
  added command line switch to start fullscreen or windowed
  modified the search for the best screen size (SDL modes are sorted by
    Y size)

 patched by Dan Scholnik (scholnik@ieee.org)
  added support for 32bpp XFree86 modes
  new update routines: 8->32bpp & 16->32bpp

 TODO: Test the HERMES code.
       Test the 16bpp->24bpp update routine
       Test the 16bpp->32bpp update routine
       Improve performance.
       Test mouse buttons (which games use them?)

***************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <SDL.h>
#include "keycodes.h"
#include "SDL-keytable.h"
#include "sysdep/sysdep_display_priv.h"

static SDL_Surface* video_surface = NULL;
static int startx, starty;
static blit_func_p blit_func;
static int scaled_height, scaled_width;
static int first_update;
static int sdl_input_grabbed = SDL_GRAB_OFF;

/* options, these get initialised by the rc-code */
static int sdl_grab_input;
static int sdl_show_cursor;
static int sdl_always_use_mouse;
static int doublebuf;

static int sdl_mapkey(struct rc_option *option, const char *arg, int priority);

struct rc_option sysdep_display_opts[] = {
  /* name, shortname, type, dest, deflt, min, max, func, help */
  { NULL, NULL, rc_link, aspect_opts, NULL, 0, 0, NULL, NULL },
  { "SDL Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
  { "doublebuf", NULL, rc_bool, &doublebuf, "1", 0, 0, NULL,
    "Use double buffering to reduce flicker/tearing" },
  { "grabinput", "gi", rc_bool, &sdl_grab_input, "0", 0, 0, NULL, "Select input grabbing (left-ctrl + delete)" },
  { "alwaysusemouse", "aum", rc_bool, &sdl_always_use_mouse, "0", 0, 0, NULL, "Always use mouse movements as input, even when not grabbed and not fullscreen (default disabled)" },
  { "cursor", "cu", rc_bool, &sdl_show_cursor, "1", 0, 0, NULL, "Show/don't show the cursor" },
  { "sdlmapkey", "sdlmk", rc_use_function, NULL, NULL, 0, 0, sdl_mapkey,
    "Set a specific key mapping, see xmamerc.dist" },
  { NULL, NULL, rc_link, mode_opts, NULL, 0, 0, NULL, NULL },
  { NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

int sysdep_display_init(void)
{
  memset(sysdep_display_properties.mode_info, 0,
    SYSDEP_DISPLAY_VIDEO_MODES * sizeof(int));
  sysdep_display_properties.mode_info[0] = SYSDEP_DISPLAY_WINDOWED | 
    SYSDEP_DISPLAY_FULLSCREEN | SYSDEP_DISPLAY_EFFECTS;
  memset(sysdep_display_properties.mode_name, 0,
    SYSDEP_DISPLAY_VIDEO_MODES * sizeof(const char *));
  sysdep_display_properties.mode_name[0] = "SDL";

  if (SDL_Init(SDL_INIT_VIDEO) < 0) {
    fprintf (stderr, "SDL: Error: %s\n",SDL_GetError());
    return 1;
  } 
  return 0;
}

void sysdep_display_exit(void)
{
  SDL_Quit();
}

static int SDL_calc_depth(const SDL_PixelFormat *pixel_format)
{
  return ((8 - pixel_format->Rloss) + (8 - pixel_format->Gloss) +
    (8 - pixel_format->Bloss));
}

int sysdep_display_driver_open(int reopen)
{
  int i,j;
  SDL_Rect** vid_modes;
  SDL_PixelFormat pixel_format;
  const SDL_VideoInfo* video_info;
  int video_flags, score, best_window = 0;
  int best_bpp = 0, best_width = 0, best_height = 0, best_score = 0;
  static int firsttime = 1;
  
  if (reopen)
    sysdep_display_effect_close();
  
  /* determine SetVideoMode flags */
  video_flags = SDL_HWSURFACE;
  if (sysdep_display_params.fullscreen)
    video_flags |= SDL_FULLSCREEN;
  if (doublebuf)
    video_flags |= SDL_DOUBLEBUF;

  /* Find a suitable mode, also determine the max size of the display */
  scaled_height = sysdep_display_params.yarbsize?
    sysdep_display_params.yarbsize:
    sysdep_display_params.height*sysdep_display_params.heightscale;
  scaled_width = ((sysdep_display_params.width+3)&~3) * 
    sysdep_display_params.widthscale;
  sysdep_display_properties.max_width  = 0;
  sysdep_display_properties.max_height = 0;
  
  for (i=0; i<5; i++)
  {
    /* We can't ask SDL which pixel formats are available, so we
       try all well known formats + the format preferred by the SDL
       videodriver, also trying the preferred format will ensure that
       we try at least one available format, so that we will always find
       some modes.
       
       The preferred format is tried last, so that if
       a just as good well known format is found this will be used instead of
       the preferred format. This is done because the effect code only supports
       well know formats, so if we can choose we want a well known format. */
    switch (i)
    {
      case 0:
        /* rgb 555 */
        pixel_format.palette = NULL;
        pixel_format.BitsPerPixel = 15;
        pixel_format.BytesPerPixel = 2;
        pixel_format.Rmask  = 0x01F << 10;
        pixel_format.Gmask  = 0x01F << 5;
        pixel_format.Bmask  = 0x01F << 0;
        pixel_format.Rshift = 10;
        pixel_format.Gshift = 5;
        pixel_format.Bshift = 0;
        pixel_format.Rloss  = 3;
        pixel_format.Gloss  = 3;
        pixel_format.Bloss  = 3;
        pixel_format.colorkey = 0;
        pixel_format.alpha  = 255;
        break;
      case 1:
        /* rgb 565 */
        pixel_format.palette = NULL;
        pixel_format.BitsPerPixel = 16;
        pixel_format.BytesPerPixel = 2;
        pixel_format.Rmask  = 0x01F << 11;
        pixel_format.Gmask  = 0x03F << 5;
        pixel_format.Bmask  = 0x01F << 0;
        pixel_format.Rshift = 11;
        pixel_format.Gshift = 5;
        pixel_format.Bshift = 0;
        pixel_format.Rloss  = 3;
        pixel_format.Gloss  = 2;
        pixel_format.Bloss  = 3;
        pixel_format.colorkey = 0;
        pixel_format.alpha  = 255;
        break;
      case 2:
        /* rgb 888 packed*/
        pixel_format.palette = NULL;
        pixel_format.BitsPerPixel = 24;
        pixel_format.BytesPerPixel = 3;
        pixel_format.Rmask  = 0x0FF << 16;
        pixel_format.Gmask  = 0x0FF << 8;
        pixel_format.Bmask  = 0x0FF << 0;
        pixel_format.Rshift = 16;
        pixel_format.Gshift = 8;
        pixel_format.Bshift = 0;
        pixel_format.Rloss  = 0;
        pixel_format.Gloss  = 0;
        pixel_format.Bloss  = 0;
        pixel_format.colorkey = 0;
        pixel_format.alpha  = 255;
        break;
      case 3:
        /* rgb 888 sparse */
        pixel_format.palette = NULL;
        pixel_format.BitsPerPixel = 32;
        pixel_format.BytesPerPixel = 4;
        pixel_format.Rmask  = 0x0FF << 16;
        pixel_format.Gmask  = 0x0FF << 8;
        pixel_format.Bmask  = 0x0FF << 0;
        pixel_format.Rshift = 16;
        pixel_format.Gshift = 8;
        pixel_format.Bshift = 0;
        pixel_format.Rloss  = 0;
        pixel_format.Gloss  = 0;
        pixel_format.Bloss  = 0;
        pixel_format.colorkey = 0;
        pixel_format.alpha  = 255;
        break;
      case 4:
        video_info = SDL_GetVideoInfo();
        pixel_format = *(video_info->vfmt);
        if (pixel_format.palette || (pixel_format.BitsPerPixel <= 8))
          continue;
        break;
    }
    vid_modes = SDL_ListModes(&pixel_format, video_flags);

    if(vid_modes == (SDL_Rect **)-1)
    {
      /* All resolutions available */
      score = mode_match(0, 0, 0, SDL_calc_depth(&pixel_format),
        pixel_format.BytesPerPixel*8);
      if (score > best_score)
      {
        best_score  = score;
        best_bpp    = pixel_format.BitsPerPixel;
        best_width  = scaled_width;
        best_height = scaled_height;
        best_window = 1;
      }
      /* also determine the max size of the display */
      sysdep_display_properties.max_width  = -1;
      sysdep_display_properties.max_height = -1;
    }
    else if (vid_modes)
    {
      for(j=0;vid_modes[j];j++)
      {
        /* No way to get the line_width from SDL, so assume that this
           is the viewport width */
        score = mode_match(vid_modes[j]->w, vid_modes[j]->h, vid_modes[j]->w,
          SDL_calc_depth(&pixel_format), pixel_format.BytesPerPixel*8);
        if (score > best_score)
        {
          best_score  = score;
          best_bpp    = pixel_format.BitsPerPixel;
          best_width  = vid_modes[j]->w;
          best_height = vid_modes[j]->h;
          best_window = 0;
        }
        /* also determine the max size of the display */
        if (vid_modes[j]->w > sysdep_display_properties.max_width)
          sysdep_display_properties.max_width  = vid_modes[j]->w;
        if (vid_modes[j]->h > sysdep_display_properties.max_height)
          sysdep_display_properties.max_height = vid_modes[j]->h;

        if (firsttime)
          fprintf(stderr, "SDL found mode:%dx%dx%d\n", vid_modes[j]->w,
            vid_modes[j]->h, pixel_format.BitsPerPixel);
      }
    }
  }
  firsttime = 0;
  
  if (best_score == 0)
  {
    fprintf(stderr, "SDL Error: could not find a suitable mode\n");
    return 1;
  }
  
  /* Set video mode */
  if (!video_surface ||
      (video_surface->w != best_width) ||
      (video_surface->h != best_height) ||
      (video_surface->format->BitsPerPixel != best_bpp))
  {
    if(! (video_surface = SDL_SetVideoMode(best_width, best_height, best_bpp,
            video_flags)))
    {
      fprintf (stderr, "SDL: Error: Setting video mode failed\n");
      return 1;
    }
    fprintf(stderr, "SDL: Using a mode with a resolution of: %dx%dx%d\n",
      best_width, best_height, best_bpp);
    if(!best_window)
    {
      mode_set_aspect_ratio((double)best_width / best_height);
      /* mode_set_aspect_ratio may have changed yarbsize */
      scaled_height = sysdep_display_params.yarbsize?
        sysdep_display_params.yarbsize:
        sysdep_display_params.height*sysdep_display_params.heightscale;
    }
  }
  else if ((video_flags & SDL_FULLSCREEN) !=
           (video_surface->flags & SDL_FULLSCREEN))
  {
    SDL_WM_ToggleFullScreen(video_surface);
  }
  /* fill the sysdep_display_properties struct */
  memset(&sysdep_display_properties.palette_info, 0, sizeof(struct
    sysdep_palette_info));
  sysdep_display_properties.palette_info.red_mask   =
    video_surface->format->Rmask;
  sysdep_display_properties.palette_info.green_mask =
    video_surface->format->Gmask;
  sysdep_display_properties.palette_info.blue_mask  =
    video_surface->format->Bmask;
  sysdep_display_properties.palette_info.depth      =
    SDL_calc_depth(video_surface->format);
  sysdep_display_properties.palette_info.bpp        =
    video_surface->format->BytesPerPixel * 8;
  sysdep_display_properties.vector_renderer         = NULL;

  if (video_surface->flags & SDL_HWSURFACE)
    sysdep_display_properties.mode_info[0] |=  SYSDEP_DISPLAY_DIRECT_FB;
  else
    sysdep_display_properties.mode_info[0] &= ~SYSDEP_DISPLAY_DIRECT_FB;
  
  /* calculate start of screen */
  startx = (video_surface->w - scaled_width ) / 2;
  starty = (video_surface->h - scaled_height) / 2;
  if (video_surface->flags & SDL_HWSURFACE)
    startx &= ~3;

  /* clear the unused area of the screen */
  for (i=0; i<2; i++)
  {
    unsigned char *video_mem;
    SDL_LockSurface(video_surface);
    video_mem = video_surface->pixels;
    
    /* top */
    memset(video_mem, 0, starty*video_surface->pitch);
    /* left and right */
    for (j=starty; j<(scaled_height+starty); j++)
    {
      /* left */
      memset(video_mem + j*video_surface->pitch, 0,
        startx * video_surface->format->BytesPerPixel);
      /* right */
      memset(video_mem + j*video_surface->pitch +
        (startx + scaled_width) * video_surface->format->BytesPerPixel,
        0, (video_surface->w - (startx + scaled_width)) *
        video_surface->format->BytesPerPixel);
    }
    /* bottom */
    memset(video_mem + (starty + scaled_height) *
      video_surface->pitch, 0,
      (video_surface->h - (starty + scaled_height)) *
      video_surface->pitch);
    
    SDL_UnlockSurface(video_surface);
    
    if (video_surface->flags & SDL_DOUBLEBUF)
      SDL_Flip(video_surface);
    else
      break;
  }

  /* Setup input */
  if (!reopen)
  {
    SDL_EventState(SDL_KEYUP, SDL_ENABLE);
    SDL_EventState(SDL_KEYDOWN, SDL_ENABLE);
    SDL_EnableUNICODE(1);
    if (sdl_grab_input)
      sdl_input_grabbed = SDL_WM_GrabInput(SDL_GRAB_ON);
  }
  
  /* Hide/Show mouse cursor? */
  if ((sdl_input_grabbed == SDL_GRAB_ON) || !sdl_show_cursor ||
      sysdep_display_params.fullscreen)
    SDL_ShowCursor(0);
  else
    SDL_ShowCursor(1);

  /* Set window title */
  SDL_WM_SetCaption(sysdep_display_params.title, NULL);
  /* let sysdep_display_update know that it's the first call after
     an (re)open */
  first_update = 1;

  /* get a blit function */
  return !(blit_func=sysdep_display_effect_open());
}

/*
 *  keyboard remapping routine
 *  invoiced in startup code
 *  returns 0-> success 1-> invalid from or to
 */
static int sdl_mapkey(struct rc_option *option, const char *arg, int priority)
{
   unsigned int from, to;
   /* ultrix sscanf() requires explicit leading of 0x for hex numbers */
   if (sscanf(arg, "0x%x,0x%x", &from, &to) == 2)
   {
      /* perform tests */
      /* fprintf(stderr,"trying to map %x to %x\n", from, to); */
      if (from >= SDLK_FIRST && from < SDLK_LAST && to >= 0 && to <= 127)
      {
         klookup[from] = to;
	 return 0;
      }
      fprintf(stderr,"Invalid keymapping %s. Ignoring...\n", arg);
   }
   return 1;
}

const char *sysdep_display_update(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, int keyb_leds, int flags)
{
  unsigned char *video_mem;
  
  /* do we need todo a full update? */
  if (first_update)
  {
    *dirty_area = *vis_in_dest_out;
    first_update = 0;
  }  

  SDL_LockSurface(video_surface);

  video_mem = video_surface->pixels;
  video_mem += startx * video_surface->format->BytesPerPixel;
  video_mem += starty * video_surface->pitch;
    
  blit_func(bitmap, vis_in_dest_out, dirty_area, palette, video_mem,
    video_surface->pitch/video_surface->format->BytesPerPixel);

  SDL_UnlockSurface(video_surface);

  if (video_surface->flags & SDL_DOUBLEBUF)
    SDL_Flip(video_surface);
  else if(!(video_surface->flags & SDL_HWSURFACE))
  {
    SDL_Rect drect;
    drect.x = startx + vis_in_dest_out->min_x;
    drect.y = starty + vis_in_dest_out->min_y;
    drect.w = vis_in_dest_out->max_x - vis_in_dest_out->min_x;
    drect.h = vis_in_dest_out->max_y - vis_in_dest_out->min_y;
    SDL_UpdateRects(video_surface,1, &drect);
  }
  
  if ((flags & SYSDEP_DISPLAY_HOTKEY_GRABMOUSE) &&
      !sysdep_display_params.fullscreen)
  {
    if(sdl_input_grabbed == SDL_GRAB_ON)
    {
      sdl_input_grabbed = SDL_WM_GrabInput(SDL_GRAB_OFF);
      if (sdl_input_grabbed == SDL_GRAB_OFF)
        sdl_grab_input = 0;
    }
    else
    {
      sdl_input_grabbed = SDL_WM_GrabInput(SDL_GRAB_ON);
      if (sdl_input_grabbed == SDL_GRAB_ON)
        sdl_grab_input = 1;
    }
    /* Show/Hide mouse cursor */
    if (sdl_show_cursor)
    {
      if (sdl_input_grabbed == SDL_GRAB_ON)
        SDL_ShowCursor(0);
      else
        SDL_ShowCursor(1);
    }
  }
      
  return NULL;
}

void sysdep_display_driver_clear_buffer(void)
{
  int i, line;
  unsigned char *video_mem;

  for (i=0; i<2; i++)
  {
    SDL_LockSurface(video_surface);

    video_mem = video_surface->pixels;
    video_mem += startx * video_surface->format->BytesPerPixel;
    video_mem += starty * video_surface->pitch;

    for (line=0; line<scaled_height; line++)
      memset(video_mem + line*video_surface->pitch, 0,
        scaled_width*video_surface->format->BytesPerPixel);

    SDL_UnlockSurface(video_surface);

    if (video_surface->flags & SDL_DOUBLEBUF)
      SDL_Flip(video_surface);
    else
      break;
  }
}

/* shut up the display */
void sysdep_display_close(void)
{
   sysdep_display_effect_close();
}

void sysdep_display_update_mouse(void)
{
   int i;
   int x,y;
   Uint8 buttons;

   if(sdl_always_use_mouse || (sdl_input_grabbed == SDL_GRAB_ON) ||
      sysdep_display_params.fullscreen)
   {
     buttons = SDL_GetRelativeMouseState( &x, &y);
     sysdep_display_mouse_data[0].deltas[0] = x;
     sysdep_display_mouse_data[0].deltas[1] = y;
     for(i=0;i<SYSDEP_DISPLAY_MOUSE_BUTTONS;i++) {
        sysdep_display_mouse_data[0].buttons[i] = buttons & (0x01 << i);
     }
   }
   else
   {
     sysdep_display_mouse_data[0].deltas[0] = 0;
     sysdep_display_mouse_data[0].deltas[1] = 0;
     for(i=0;i<SYSDEP_DISPLAY_MOUSE_BUTTONS;i++) {
        sysdep_display_mouse_data[0].buttons[i] = 0;
     }
   }
}

int sysdep_display_driver_update_keyboard() 
{
   struct sysdep_display_keyboard_event kevent;
   SDL_Event event;
   int retval = 0;

   if (video_surface) {
      while(SDL_PollEvent(&event)) {
         kevent.press = 0;
         
         switch (event.type)
         {
            case SDL_KEYDOWN:
               kevent.press = 1;
            case SDL_KEYUP:
               kevent.scancode = klookup[event.key.keysym.sym];
               kevent.unicode = event.key.keysym.unicode;
               sysdep_display_params.keyboard_handler(&kevent);
               if(!kevent.scancode)
                  fprintf (stderr, "Unknown symbol 0x%x\n",
                     event.key.keysym.sym);
#ifdef SDL_DEBUG
               fprintf (stderr, "Key %s %ssed\n",
                  SDL_GetKeyName(event.key.keysym.sym),
                  kevent.press? "pres":"relea");
#endif
               break;
            case SDL_QUIT:
               retval |= SYSDEP_DISPLAY_QUIT_REQUESTED;
               break;
    	    case SDL_JOYAXISMOTION:   
	    case SDL_JOYBUTTONDOWN:
	    case SDL_JOYBUTTONUP:
	       /* ignore, these are polled by the SDL joystick driver */
               break;
            default:
#ifdef SDL_DEBUG
               fprintf(stderr, "SDL: Debug: Other event\n");
#endif /* SDL_DEBUG */
               break;
         }
      }
   }
   return retval;
}
