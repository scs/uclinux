/***************************************************************************

 Linux libGGI driver by Gabriele Boccone - clayton@dist.unige.it

  Something is recycled (and/or tweaked) from svgalib.c. This is only
  a "Quick and Dirty Hack"(TM) to make things interesting.

  Please if you test GGI-mame send me a mail, saying: "It works on my system"
  or "It does not work on my system", and what kind of computer you tested
  GGI-mame on. If you also want to send me sugar, coffee, chocolate, etc,
  feel free to send it by e-mail.

  Adapted for xmame-0.31 by Christian Groessler - cpg@aladdin.de

  * tested with GGI 2.0 Beta2 *
***************************************************************************/
#ifdef ggi
#define __GGI_C

#include <ggi/ggi.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/*#define KEY_DEBUG*/
/*#define GGI_DEBUG*/

#include "keycodes.h"
#include "sysdep/sysdep_display_priv.h"

static ggi_visual_t vis = NULL;
static ggi_mode mode;
static int scaled_width,scaled_height;
static int startx,starty;
static unsigned char *video_mem;
static int video_width;
static int video_update_type;
static unsigned char *doublebuffer_buffer = NULL; /* also used for scaling */
static blit_func_p blit_func;
static int lastmouse[SYSDEP_DISPLAY_MOUSE_AXES]={0,0,0,0,0,0,0,0};
static int use_linear;

struct rc_option sysdep_display_opts[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
   { NULL, NULL, rc_link, aspect_opts, NULL, 0, 0, NULL, NULL },
   { "GGI Related",	NULL,			rc_seperator,	NULL,
     NULL,		0,			0,		NULL,
     NULL },
   { "linear",		NULL,			rc_bool,	&use_linear,
     "0",		0,			0,		NULL,
     "Enable/disable use of linear framebuffer (fast)" },
   { NULL, NULL, rc_link, mode_opts, NULL, 0, 0, NULL, NULL },
   { NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

int sysdep_display_init(void)
{
        /* make sure that the mode doesn't match on the first open */
        mode.visible.x = -1;
        
	memset(sysdep_display_properties.mode_info, 0,
			SYSDEP_DISPLAY_VIDEO_MODES * sizeof(int));
	sysdep_display_properties.mode_info[0] =
		SYSDEP_DISPLAY_WINDOWED | SYSDEP_DISPLAY_EFFECTS;
	memset(sysdep_display_properties.mode_name, 0,
			SYSDEP_DISPLAY_VIDEO_MODES * sizeof(const char *));
	sysdep_display_properties.mode_name[0] = "GGI";

#ifdef GGI_DEBUG
	fprintf(stderr,"sysdep_init called\n");
#endif

	if (ggiInit())
	{
		fprintf(stderr, "Unable to initialize GGI subsystem!\n"); /* sounds good, doesn't it? */
		return 1;
	}

	return 0;
}

void sysdep_display_exit(void)
{
#ifdef GGI_DEBUG
    fprintf(stderr,"sysdep_close called\n");
#endif
    ggiExit();
}

int sysdep_display_driver_open(int reopen)
{
  ggi_graphtype type = 0;
  ggi_mode sug_mode, best_mode;
  const ggi_directbuffer *direct_buf = NULL;
  ggi_pixelformat *pixel_format = NULL;
  int i, score, best_window = 0, best_score = 0;
  unsigned char *video_start;
  static int firsttime = 1;
  
#ifdef GGI_DEBUG
  fprintf(stderr,"sysdep_display_driver_open called\n");
#endif

  if (!reopen)
  {
    /* some GGI stuff */
    vis = ggiOpen(NULL);
    if (!vis)
    {
      fprintf(stderr, "GGI Error: could not open display\n");
      return 1;
    }
    ggiSetFlags(vis, GGIFLAG_ASYNC);
    ggiSetEventMask(vis, emKey | emPointer);
  }
  else
  {
    sysdep_display_effect_close();
    if (doublebuffer_buffer)
    {
      free(doublebuffer_buffer);
      doublebuffer_buffer = NULL;
    }
  }

  /* Find a suitable mode, also determine the max size of the display */
  scaled_height = sysdep_display_params.yarbsize?
    sysdep_display_params.yarbsize:
    sysdep_display_params.height*sysdep_display_params.heightscale;
  scaled_width = ((sysdep_display_params.width+3)&~3) * 
    sysdep_display_params.widthscale;
  sysdep_display_properties.max_width  = 0;
  sysdep_display_properties.max_height = 0;
  /* shutup warnings */
  memset(&best_mode, 0, sizeof(ggi_mode));
  
  for (i=0; i<4; i++)
  {
    /* We can't ask GGI which pixel formats are available, so we
       try all well known formats */
    switch (i)
    {
      case 0:
        /* rgb 555 */
        type = GT_15BIT;
        break;
      case 1:
        /* rgb 565 */
        type = GT_16BIT;
        break;
      case 2:
        /* rgb 888 packed*/
        type = GT_24BIT;
        break;
      case 3:
        /* rgb 888 sparse */
        type = GT_32BIT;
        break;
    }

    /* First try exact game resolution... */
    if (ggiCheckGraphMode(vis, sysdep_display_params.width *
         sysdep_display_params.widthscale, scaled_height, scaled_width,
         GGI_AUTO, type, &sug_mode) == 0)
    {
      /* Assume all resolutions available */
      score = mode_match(0, 0, 0, GT_DEPTH(type), GT_SIZE(type));
      if (score > best_score)
      {
        best_score  = score;
        best_mode   = sug_mode;
        best_window = 1;
      }
      /* also determine the max size of the display */
      sysdep_display_properties.max_width  = -1;
      sysdep_display_properties.max_height = -1;
    }
    else
    {
      /* GRRR no way to list modes, but GGI will suggest a larger mode
         then requested if available, so start with 1x1, then list all
         widths and per width all heights (sigh) */
      int width = 1, height = 1;

      ggiCheckGraphMode(vis, width, height, GGI_AUTO,
        GGI_AUTO, type, &sug_mode);
        
      /* have we got the requested type? */
      if (sug_mode.graphtype == type)
      {
        /* while we've got a bigger width suggested then the last tried */
        while (sug_mode.visible.x >= width)
        {
          while (sug_mode.visible.y >= height)
          {
            score = mode_match(sug_mode.visible.x, sug_mode.visible.y,
              sug_mode.virt.x, GT_DEPTH(type), GT_SIZE(type));
            if (score > best_score)
            {
              best_score  = score;
              best_mode   = sug_mode;
              best_window = 0;
            }

            /* also determine the max size of the display */
            if (sug_mode.visible.x > sysdep_display_properties.max_width)
              sysdep_display_properties.max_width  = sug_mode.visible.x;
            if (sug_mode.visible.y > sysdep_display_properties.max_height)
              sysdep_display_properties.max_height = sug_mode.visible.y;

            if (firsttime)
              fprintf(stderr, "GGI found mode:%dx%dx%d\n", sug_mode.visible.x,
                sug_mode.visible.y, (GT_DEPTH(type)==24)? GT_SIZE(type):
                GT_DEPTH(type));
            
            height = sug_mode.visible.y + 1;
            ggiCheckGraphMode(vis, width, height, GGI_AUTO,
              GGI_AUTO, type, &sug_mode);
          }
          width  = sug_mode.visible.x + 1;
          height = 1;
          ggiCheckGraphMode(vis, width, height, GGI_AUTO,
            GGI_AUTO, type, &sug_mode);
        }
      }
    }
  }
  firsttime = 0;

  if (best_score == 0)
  {
    fprintf(stderr, "GGI Error: could not find a suitable mode\n");
    return 1;
  }
  
  if (memcmp(&mode, &best_mode, sizeof(ggi_mode)))
  {
    if (ggiSetMode(vis, &best_mode) != 0)
    {
      fprintf(stderr, "GGI Error: could not set mode: %dx%dx%d\n",
        best_mode.visible.x, best_mode.visible.y,
        (GT_DEPTH(best_mode.graphtype)==24)? GT_SIZE(best_mode.graphtype):
        GT_DEPTH(best_mode.graphtype));
      return 1;
    }
    mode = best_mode;
  }

  if (best_window)
  {
    startx = ((mode.visible.x - sysdep_display_params.width *
      sysdep_display_params.widthscale) / 2) & ~3;
  }
  else
  {
    mode_set_aspect_ratio((double)mode.visible.x / mode.visible.y);
    /* mode_set_aspect_ratio may have changed yarbsize */
    scaled_height = sysdep_display_params.yarbsize?
      sysdep_display_params.yarbsize:
      sysdep_display_params.height*sysdep_display_params.heightscale;
    startx = ((mode.visible.x - scaled_width ) / 2) & ~3;
  }
  starty = (mode.visible.y - scaled_height) / 2;

  fprintf(stderr,"GGI: using mode %dx%dx%d, starting at %dx%d\n", mode.visible.x, mode.visible.y,
    (GT_DEPTH(mode.graphtype)==24)? GT_SIZE(mode.graphtype):
    GT_DEPTH(mode.graphtype), startx, starty);
    
  /* try to get a directbuf and through this the pixel format */
  if (ggiDBGetNumBuffers(vis) && (direct_buf = ggiDBGetBuffer(vis,0)))
  {
    /* all standard layouts have a pixel format, but this is hidden
       in the layout union instead of being "global" GRRRR. */
    switch(direct_buf->layout)
    {
      case blPixelLinearBuffer:
        pixel_format = direct_buf->buffer.plb.pixelformat;
        break;
      case blPixelPlanarBuffer:
        pixel_format = direct_buf->buffer.plan.pixelformat;
        break;
      case blSampleLinearBuffer:
        pixel_format = direct_buf->buffer.slb.pixelformat[0];
        break;
      case blSamplePlanarBuffer:
        pixel_format = direct_buf->buffer.splan.pixelformat[0];
        break;
      default: /* shut op enumeration warnings */
        break;
    }
  }

  /* fill the sysdep_display_properties struct */
  memset(&sysdep_display_properties.palette_info, 0, sizeof(struct
    sysdep_palette_info));
  if (pixel_format)
  {
    sysdep_display_properties.palette_info.red_mask  =pixel_format->red_mask;
    sysdep_display_properties.palette_info.green_mask=pixel_format->green_mask;
    sysdep_display_properties.palette_info.blue_mask =pixel_format->blue_mask;
  }
  else
  {
    /* No way to get the pixel format of the choisen mode, you
       can only get the default pixel format, great API guys (NOT!) */
    switch (GT_DEPTH(mode.graphtype))
    {
      case 15:
              sysdep_display_properties.palette_info.red_mask   = 0x001F;
              sysdep_display_properties.palette_info.green_mask = 0x03E0;
              sysdep_display_properties.palette_info.blue_mask  = 0xEC00;
              break;
      case 16:
              sysdep_display_properties.palette_info.red_mask   = 0xF800;
              sysdep_display_properties.palette_info.green_mask = 0x07E0;
              sysdep_display_properties.palette_info.blue_mask  = 0x001F;
              break;
      case 24:
              sysdep_display_properties.palette_info.red_mask   = 0xFF0000;
              sysdep_display_properties.palette_info.green_mask = 0x00FF00;
              sysdep_display_properties.palette_info.blue_mask  = 0x0000FF;
              break;
    }
  }
  sysdep_display_properties.palette_info.depth = GT_DEPTH(mode.graphtype);
  sysdep_display_properties.palette_info.bpp   = GT_SIZE(mode.graphtype);
  sysdep_display_properties.vector_renderer    = NULL;

  /* can we do linear ? */
  if (use_linear && direct_buf &&
     (direct_buf->type & GGI_DB_NORMAL) &&
     (direct_buf->page_size == 0) &&
     !(direct_buf->noaccess & 0x04) && /* we align our accesses to 4 pixels */
     !(direct_buf->align & ~0x07) &&   /* we align our accesses to 4 pixels */
     (direct_buf->layout == blPixelLinearBuffer))
  {
          video_mem = direct_buf->write;
          video_mem += startx * GT_SIZE(mode.graphtype) / 8;
          video_mem += starty * direct_buf->buffer.plb.stride;
          video_width = direct_buf->buffer.plb.stride;
          video_update_type = 0;
  }
  else
  {
          /* do we need to blit to a doublebuffer buffer because using
             effects, scaling etc. */
	  if (!sysdep_display_blit_dest_bitmap_equals_src_bitmap())
	  {
	    doublebuffer_buffer = malloc(scaled_width*scaled_height*
	      (GT_SIZE(mode.graphtype) / 8));
            if (!doublebuffer_buffer)
            {
                    fprintf(stderr, "GGI Error: Couldn't allocate doublebuffer buffer\n");
                    return 1;
            }
	    video_update_type=2;
          }
	  else
	    video_update_type=1;
  }

  /* get a blit func, GRRR no way to detect if we have a hardware surface,
     so assume one when using a LFB. */
  if (video_update_type == 0)
    sysdep_display_properties.mode_info[0] |=  SYSDEP_DISPLAY_DIRECT_FB;
  else
    sysdep_display_properties.mode_info[0] &= ~SYSDEP_DISPLAY_DIRECT_FB;
  
  /* clear the unused area of the screen */
  switch(video_update_type)
  {
    case 0: /* linear */
      video_start = direct_buf->write;
      /* top */
      memset(video_start, 0, starty*video_width);
      /* left and right */
      for (i=starty; i<(scaled_height+starty); i++)
      {
        /* left */
        memset(video_start + i*video_width, 0, startx *
          GT_SIZE(mode.graphtype) / 8);
        /* right */
        memset(video_start + i*video_width + (startx + scaled_width) *
          GT_SIZE(mode.graphtype) / 8, 0, (mode.visible.x -
          (startx + scaled_width)) * GT_SIZE(mode.graphtype) / 8);
      }
      /* bottom */
      memset(video_start + (starty + scaled_height) * video_width, 0,
        (mode.visible.y - (starty + scaled_height)) * video_width);
      break;
    case 1: /* non linear bitmap equals framebuffer */
    case 2: /* non linear bitmap needs conversion before it can be blitted */
      ggiSetGCForeground(vis, 0);
      /* top */
      ggiDrawBox(vis, 0, 0, mode.visible.x, starty);
      /* left */
      ggiDrawBox(vis, 0, starty, startx, scaled_height);
      /* right */
      ggiDrawBox(vis, startx + scaled_width, starty,
         mode.visible.x - (startx + scaled_width),
         scaled_height);
      /* bottom */
      ggiDrawBox(vis, 0, starty + scaled_height, mode.visible.x,
         mode.visible.y - (starty + scaled_height));
      break;
  }

  /* get a blit function */
  return !(blit_func=sysdep_display_effect_open());
}


/*
 * close down the display
 */
void sysdep_display_close(void)
{
#ifdef GGI_DEBUG
    fprintf(stderr,"sysdep_display_close called\n");
#endif
    sysdep_display_effect_close();
    if (doublebuffer_buffer)
    {
      free(doublebuffer_buffer);
      doublebuffer_buffer = NULL;
    }
    if (vis) {
      ggiClose(vis);
      vis=NULL;
    }
    /* make sure that the mode doesn't match on the first open */
    mode.visible.x = -1;
#ifdef GGI_DEBUG
    fprintf(stderr,"sysdep_display_close finished\n");
#endif
}

/*
 * Update the display.
 */
const char *sysdep_display_update(mame_bitmap *bitmap,
		rectangle *vis_in_dest_out,
		rectangle *dirty_area,
		struct sysdep_palette_struct *palette, int keyb_leds,
		int flags)
{
  int y;
  
  switch(video_update_type)
  {
    case 0: /* linear */
      blit_func(bitmap, vis_in_dest_out, dirty_area, palette, video_mem,
        video_width);
      break;
    case 1: /* non linear bitmap equals framebuffer */
      sysdep_display_check_bounds(bitmap, vis_in_dest_out, dirty_area, 3);
      for (y=0; y < (vis_in_dest_out->max_y-vis_in_dest_out->min_y); y++)
      {
        ggiPutHLine(vis, startx + vis_in_dest_out->min_x, starty +
          vis_in_dest_out->min_y + y,
          vis_in_dest_out->max_x - vis_in_dest_out->min_x,
          ((unsigned char *)(bitmap->line[y+dirty_area->min_y])) +
          dirty_area->min_x * GT_SIZE(mode.graphtype) / 8);
      }
      break;
    case 2: /* non linear bitmap needs conversion before it can be blitted */
      blit_func(bitmap, vis_in_dest_out, dirty_area, palette,
        doublebuffer_buffer, scaled_width);
      for (y = vis_in_dest_out->min_y; y < vis_in_dest_out->max_y; y++)
      {
        ggiPutHLine(vis, startx + vis_in_dest_out->min_x, y + starty,
          vis_in_dest_out->max_x - vis_in_dest_out->min_x,
          doublebuffer_buffer + (y * scaled_width + vis_in_dest_out->min_x) *
          GT_SIZE(mode.graphtype) / 8);
      }
      break;
  }

  ggiFlush(vis);
  return NULL;
}

void sysdep_display_driver_clear_buffer(void)
{
  int line;
  switch(video_update_type)
  {
    case 0: /* linear */
      for (line=0; line<scaled_height; line++)
        memset(video_mem + line*video_width, 0, scaled_width *
        GT_SIZE(mode.graphtype) / 8);
      break;
    case 1: /* non linear bitmap equals framebuffer */
      ggiDrawBox(vis, startx, starty, scaled_width, scaled_height);
      break;
    case 2: /* non linear bitmap needs conversion before it can be blitted */
      memset(doublebuffer_buffer, 0,
        scaled_width * scaled_height * GT_SIZE(mode.graphtype) / 8);
      break;
  }
}

int ggi_key(ggi_event *ev)
{
    unsigned int keycode=KEY_NONE;
    int label = ev->key.label;

#ifdef KEY_DEBUG
    fprintf(stderr,
        "Keyevent detected: sym = 0x%02x, code = 0x%02x, label = 0x%02x\n",
        ev->key.sym, ev->key.button, label);
#endif

    switch (label >> 8)
    {
       case GII_KT_LATIN1:
          switch (label) { /* for now, the simple way */
              case GIIUC_BackSpace:  keycode = KEY_BACKSPACE;  break;
              case GIIUC_Tab:        keycode = KEY_TAB;        break;
              case GIIUC_Linefeed:   keycode = KEY_ENTER;      break;
              case GIIUC_Return:     keycode = KEY_ENTER;      break;
              case GIIUC_Escape:     keycode = KEY_ESC;        break;
              case GIIUC_Delete:     keycode = KEY_DEL;        break;
              case GIIUC_Space:      keycode = KEY_SPACE;      break;
              case GIIUC_Exclam:     keycode = KEY_1;          break;
              case GIIUC_QuoteDbl:   keycode = KEY_QUOTE;      break;
              case GIIUC_Hash:       keycode = KEY_3;          break;
              case GIIUC_Dollar:     keycode = KEY_4;          break;
              case GIIUC_Percent:    keycode = KEY_5;          break;
              case GIIUC_Ampersand:  keycode = KEY_7;          break;
              case GIIUC_Apostrophe: keycode = KEY_QUOTE;      break;
              case GIIUC_ParenLeft:  keycode = KEY_9;          break;
              case GIIUC_ParenRight: keycode = KEY_0;          break;
              case GIIUC_Asterisk:   keycode = KEY_ASTERISK;   break;
              case GIIUC_Plus:       keycode = KEY_EQUALS;     break;
              case GIIUC_Comma:      keycode = KEY_COMMA;      break;
              case GIIUC_Minus:      keycode = KEY_MINUS;      break;
              case GIIUC_Period:     keycode = KEY_STOP;       break;
              case GIIUC_Slash:      keycode = KEY_SLASH;      break;
              case GIIUC_0:          keycode = KEY_0;          break;
              case GIIUC_1:          keycode = KEY_1;          break;
              case GIIUC_2:          keycode = KEY_2;          break;
              case GIIUC_3:          keycode = KEY_3;          break;
              case GIIUC_4:          keycode = KEY_4;          break;
              case GIIUC_5:          keycode = KEY_5;          break;
              case GIIUC_6:          keycode = KEY_6;          break;
              case GIIUC_7:          keycode = KEY_7;          break;
              case GIIUC_8:          keycode = KEY_8;          break;
              case GIIUC_9:          keycode = KEY_9;          break;
              case GIIUC_Colon:      keycode = KEY_COLON;      break;
              case GIIUC_Semicolon:  keycode = KEY_COLON;      break;
              case GIIUC_Less:       keycode = KEY_COMMA;      break;
              case GIIUC_Equal:      keycode = KEY_EQUALS;     break;
              case GIIUC_Greater:    keycode = KEY_STOP;       break;
              case GIIUC_Question:   keycode = KEY_SLASH;      break;
              case GIIUC_At:         keycode = KEY_2;          break;
              case GIIUC_A:          keycode = KEY_A;          break;
              case GIIUC_B:          keycode = KEY_B;          break;
              case GIIUC_C:          keycode = KEY_C;          break;
              case GIIUC_D:          keycode = KEY_D;          break;
              case GIIUC_E:          keycode = KEY_E;          break;
              case GIIUC_F:          keycode = KEY_F;          break;
              case GIIUC_G:          keycode = KEY_G;          break;
              case GIIUC_H:          keycode = KEY_H;          break;
              case GIIUC_I:          keycode = KEY_I;          break;
              case GIIUC_J:          keycode = KEY_J;          break;
              case GIIUC_K:          keycode = KEY_K;          break;
              case GIIUC_L:          keycode = KEY_L;          break;
              case GIIUC_M:          keycode = KEY_M;          break;
              case GIIUC_N:          keycode = KEY_N;          break;
              case GIIUC_O:          keycode = KEY_O;          break;
              case GIIUC_P:          keycode = KEY_P;          break;
              case GIIUC_Q:          keycode = KEY_Q;          break;
              case GIIUC_R:          keycode = KEY_R;          break;
              case GIIUC_S:          keycode = KEY_S;          break;
              case GIIUC_T:          keycode = KEY_T;          break;
              case GIIUC_U:          keycode = KEY_U;          break;
              case GIIUC_V:          keycode = KEY_V;          break;
              case GIIUC_W:          keycode = KEY_W;          break;
              case GIIUC_X:          keycode = KEY_X;          break;
              case GIIUC_Y:          keycode = KEY_Y;          break;
              case GIIUC_Z:          keycode = KEY_Z;          break;
              case GIIUC_BracketLeft:  keycode = KEY_OPENBRACE;  break;
              case GIIUC_BackSlash:    keycode = KEY_BACKSLASH;  break;
              case GIIUC_BracketRight: keycode = KEY_CLOSEBRACE; break;
              case GIIUC_Circumflex:   keycode = KEY_6;          break;
              case GIIUC_Underscore:   keycode = KEY_MINUS;      break;
              case GIIUC_Grave:        keycode = KEY_TILDE;      break;
              case GIIUC_a:          keycode = KEY_A;          break;
              case GIIUC_b:          keycode = KEY_B;          break;
              case GIIUC_c:          keycode = KEY_C;          break;
              case GIIUC_d:          keycode = KEY_D;          break;
              case GIIUC_e:          keycode = KEY_E;          break;
              case GIIUC_f:          keycode = KEY_F;          break;
              case GIIUC_g:          keycode = KEY_G;          break;
              case GIIUC_h:          keycode = KEY_H;          break;
              case GIIUC_i:          keycode = KEY_I;          break;
              case GIIUC_j:          keycode = KEY_J;          break;
              case GIIUC_k:          keycode = KEY_K;          break;
              case GIIUC_l:          keycode = KEY_L;          break;
              case GIIUC_m:          keycode = KEY_M;          break;
              case GIIUC_n:          keycode = KEY_N;          break;
              case GIIUC_o:          keycode = KEY_O;          break;
              case GIIUC_p:          keycode = KEY_P;          break;
              case GIIUC_q:          keycode = KEY_Q;          break;
              case GIIUC_r:          keycode = KEY_R;          break;
              case GIIUC_s:          keycode = KEY_S;          break;
              case GIIUC_t:          keycode = KEY_T;          break;
              case GIIUC_u:          keycode = KEY_U;          break;
              case GIIUC_v:          keycode = KEY_V;          break;
              case GIIUC_w:          keycode = KEY_W;          break;
              case GIIUC_x:          keycode = KEY_X;          break;
              case GIIUC_y:          keycode = KEY_Y;          break;
              case GIIUC_z:          keycode = KEY_Z;          break;
              case GIIUC_BraceLeft:  keycode = KEY_OPENBRACE;  break;
              case GIIUC_Pipe:       keycode = KEY_BACKSLASH;  break;
              case GIIUC_BraceRight: keycode = KEY_CLOSEBRACE; break;
              case GIIUC_Tilde:      keycode = KEY_TILDE;      break;
          }
          break;
       case GII_KT_SPEC:
          switch (label) { /* for now, the simple way */
              case GIIK_Break:       keycode = KEY_PAUSE;      break;
              case GIIK_ScrollForw:  keycode = KEY_PGUP;       break;
              case GIIK_ScrollBack:  keycode = KEY_PGDN;       break;
              case GIIK_Menu:        keycode = KEY_MENU;       break;
              case GIIK_Cancel:      keycode = KEY_ESC;        break;
              case GIIK_PrintScreen: keycode = KEY_PRTSCR;     break;
              case GIIK_Execute:     keycode = KEY_ENTER;      break;
              case GIIK_Begin:       keycode = KEY_HOME;       break;
              case GIIK_Clear:       keycode = KEY_DEL;        break;
              case GIIK_Insert:      keycode = KEY_INSERT;     break;
              case GIIK_Select:      keycode = KEY_ENTER_PAD;  break;
              case GIIK_Pause:       keycode = KEY_PAUSE;      break;
              case GIIK_SysRq:       keycode = KEY_PRTSCR;     break;
              case GIIK_ModeSwitch:  keycode = KEY_ALTGR;      break;
              case GIIK_Up:          keycode = KEY_UP;         break;
              case GIIK_Down:        keycode = KEY_DOWN;       break;
              case GIIK_Left:        keycode = KEY_LEFT;       break;
              case GIIK_Right:       keycode = KEY_RIGHT;      break;
              case GIIK_PageUp:      keycode = KEY_PGUP;       break;
              case GIIK_PageDown:    keycode = KEY_PGDN;       break;
              case GIIK_Home:        keycode = KEY_HOME;       break;
              case GIIK_End:         keycode = KEY_END;        break;
          }
          break;
       case GII_KT_FN:
          switch (label) { /* for now, the simple way */
              case GIIK_F1:      keycode = KEY_F1;     break;
              case GIIK_F2:      keycode = KEY_F2;     break;
              case GIIK_F3:      keycode = KEY_F3;     break;
              case GIIK_F4:      keycode = KEY_F4;     break;
              case GIIK_F5:      keycode = KEY_F5;     break;
              case GIIK_F6:      keycode = KEY_F6;     break;
              case GIIK_F7:      keycode = KEY_F7;     break;
              case GIIK_F8:      keycode = KEY_F8;     break;
              case GIIK_F9:      keycode = KEY_F9;     break;
              case GIIK_F10:     keycode = KEY_F10;    break;
              case GIIK_F11:     keycode = KEY_F11;    break;
              case GIIK_F12:     keycode = KEY_F12;    break;
          }
          break;
       case GII_KT_PAD:
          switch (label) { /* for now, the simple way */
              case GIIK_P0:          keycode = KEY_0_PAD;      break;
              case GIIK_P1:          keycode = KEY_1_PAD;      break;
              case GIIK_P2:          keycode = KEY_2_PAD;      break;
              case GIIK_P3:          keycode = KEY_3_PAD;      break;
              case GIIK_P4:          keycode = KEY_4_PAD;      break;
              case GIIK_P5:          keycode = KEY_5_PAD;      break;
              case GIIK_P6:          keycode = KEY_6_PAD;      break;
              case GIIK_P7:          keycode = KEY_7_PAD;      break;
              case GIIK_P8:          keycode = KEY_8_PAD;      break;
              case GIIK_P9:          keycode = KEY_9_PAD;      break;
              case GIIK_PA:          keycode = KEY_A;          break;
              case GIIK_PB:          keycode = KEY_B;          break;
              case GIIK_PC:          keycode = KEY_C;          break;
              case GIIK_PD:          keycode = KEY_D;          break;
              case GIIK_PE:          keycode = KEY_E;          break;
              case GIIK_PF:          keycode = KEY_F;          break;
              case GIIK_PPlus:       keycode = KEY_PLUS_PAD;   break;
              case GIIK_PMinus:      keycode = KEY_MINUS_PAD;  break;
              case GIIK_PSlash:      keycode = KEY_SLASH_PAD;  break;
              case GIIK_PAsterisk:   keycode = KEY_ASTERISK;   break;
              case GIIK_PEqual:       keycode = KEY_ENTER_PAD;  break;
              case GIIK_PSeparator:  keycode = KEY_DEL_PAD;    break;
              case GIIK_PDecimal:    keycode = KEY_DEL_PAD;    break;
              case GIIK_PParenLeft:  keycode = KEY_9_PAD;      break;
              case GIIK_PParenRight: keycode = KEY_0_PAD;      break;
              case GIIK_PSpace:      keycode = KEY_SPACE;      break;
              case GIIK_PEnter:      keycode = KEY_ENTER_PAD;  break;
              case GIIK_PTab:        keycode = KEY_TAB;        break;
              case GIIK_PBegin:      keycode = KEY_HOME;       break;
              case GIIK_PF1:         keycode = KEY_F1;         break;
              case GIIK_PF2:         keycode = KEY_F2;         break;
              case GIIK_PF3:         keycode = KEY_F3;         break;
              case GIIK_PF4:         keycode = KEY_F4;         break;
              case GIIK_PF5:         keycode = KEY_F5;         break;
              case GIIK_PF6:         keycode = KEY_F6;         break;
              case GIIK_PF7:         keycode = KEY_F7;         break;
              case GIIK_PF8:         keycode = KEY_F8;         break;
              case GIIK_PF9:         keycode = KEY_F9;         break;
          }
          break;
       case GII_KT_MOD:
          switch (label) { /* for now, the simple way */
              case GIIK_ShiftL:      keycode = KEY_LSHIFT;     break;
              case GIIK_ShiftR:      keycode = KEY_RSHIFT;     break;
              case GIIK_CtrlL:       keycode = KEY_LCONTROL;   break;
              case GIIK_CtrlR:       keycode = KEY_RCONTROL;   break;
              case GIIK_AltL:        keycode = KEY_ALT;        break;
              case GIIK_AltR:        keycode = KEY_ALTGR;      break;
              case GIIK_MetaL:       keycode = KEY_LWIN;       break;
              case GIIK_MetaR:       keycode = KEY_RWIN;       break;
              case GIIK_ShiftLock:   keycode = KEY_CAPSLOCK;   break;
              case GIIK_CapsLock:    keycode = KEY_CAPSLOCK;   break;
              case GIIK_NumLock:     keycode = KEY_NUMLOCK;    break;
              case GIIK_ScrollLock:  keycode = KEY_SCRLOCK;    break;
          }
          break;
       case GII_KT_DEAD:
          switch (label) { /* for now, the simple way */
          }
          break;
    }
#ifdef KEY_DEBUG
    fprintf(stderr,"returning keycode = %d\n",keycode);
#endif
    return(keycode);
}

int sysdep_display_driver_update_keyboard(void)
{
    ggi_event_mask em = emAll; /*emKeyPress | emKeyRelease;*/
    ggi_event ev;
    struct timeval to = { 0 , 0 };
    struct sysdep_display_keyboard_event event;

    if (vis) {
        while(ggiEventPoll(vis,em,&to)) {
            event.press = 0;
            
            ggiEventRead(vis,&ev,em);

            switch(ev.any.type) {
              case evKeyPress:
                  event.press = 1;
              case evKeyRelease:
                  event.scancode = ggi_key(&ev);
                  event.unicode = ev.key.sym;
                  sysdep_display_params.keyboard_handler(&event);
                  break;
            }

            to.tv_sec=to.tv_usec=0;
        }
    }
    return 0;
}


/*
 * mouse not really tested
 */
void sysdep_display_update_mouse(void)
{
    ggi_event_mask em = emPtrButtonPress | emPtrButtonRelease | emPtrMove;
    ggi_event ev;
    struct timeval to = { 0 , 0 };
    int bi;

    if (vis) {
        while(ggiEventPoll(vis,em,&to)) {
            ggiEventRead(vis,&ev,em);
            bi = 0;

            switch(ev.any.type) {

              case evPtrButtonPress:
                  bi = 1;
              case evPtrButtonRelease:
                  if (ev.pbutton.button < SYSDEP_DISPLAY_MOUSE_BUTTONS)
                     sysdep_display_mouse_data[0].buttons[ev.pbutton.button] = bi;
                  break;
              case evPtrAbsolute:
                  sysdep_display_mouse_data[0].deltas[0] = lastmouse[0] - ev.pmove.x;
                  sysdep_display_mouse_data[0].deltas[1] = lastmouse[1] - ev.pmove.y;
                  lastmouse[0] = ev.pmove.x;
                  lastmouse[1] = ev.pmove.y;
                  break;
              case evPtrRelative:
                  sysdep_display_mouse_data[0].deltas[0] = ev.pmove.x;
                  sysdep_display_mouse_data[0].deltas[1] = ev.pmove.y;
                  lastmouse[0] += ev.pmove.x;
                  lastmouse[1] += ev.pmove.y;
                  break;
            }
            to.tv_sec=to.tv_usec=0;
        }
    }
    return;
}

void sysdep_set_leds(int leds)
{
}
#endif /* ifdef ggi */
