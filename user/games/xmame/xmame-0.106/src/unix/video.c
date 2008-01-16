/*
 * X-Mame generic video code
 *
 */
#define __VIDEO_C_
#include <math.h>
#include <stdio.h>

#include "driver.h"
#include "profiler.h"
#include "artwork.h"
#include "usrintrf.h"
#include "vidhrdw/vector.h"
#include "mamedbg.h"
#ifdef MESS
#include "mess/mesintrf.h"
#endif

#include "xmame.h"
#include "devices.h"
#include "sysdep/misc.h"
#include "sysdep/sysdep_display.h"

#define FRAMESKIP_DRIVER_COUNT 2
static int frameskipper = 0;
static int debugger_has_focus = 0;
static int show_effect_or_scale = 0;
static int show_status = 0;
static const char *status_msg = NULL;
static int normal_params_changed = 0;
static char *mngwrite = NULL;

/* options these are initialised through the rc_option struct */
static float f_beam;
static float f_flicker;
static float f_intensity;
static int use_auto_double;
static int use_hw_vectors;
static int use_artwork;
static int use_backdrops;
static int use_overlays;
static int use_bezels;
static int video_norotate;
static int video_flipy;
static int video_flipx;
static int video_ror;
static int video_rol;
static int video_autoror;
static int video_autorol;
static int user_widthscale;
static int user_heightscale;
static int user_yarbsize;
static int user_effect;

static struct sysdep_palette_struct *normal_palette = NULL;
static struct sysdep_palette_struct *debug_palette  = NULL;

static struct sysdep_display_open_params normal_params;
static struct sysdep_display_open_params debug_params = {
  0, 0, 16, 0, 0, 0, NAME " debug window", 0, 1, 1, 0, 0, 0, 0.0,
  xmame_keyboard_register_event, NULL, NULL };

/* Visual area override related vars, for dual monitor games hacks */
static rectangle game_vis_area;
static rectangle game_vis_area_override_rect[3] = {
  {-1,-1,-1,-1},
  {-1,-1,-1,-1},
  {-1,-1,-1,-1} };
double game_vis_area_override_aspect[3] = { -1.0, -1.0, -1.0 };
int game_vis_area_override_index = 0;

/* average FPS calculation */
static cycles_t start_time = 0;
static cycles_t end_time;
static int frames_displayed;
static int frames_to_display;

extern UINT8 trying_to_quit;

/* some prototypes */
static int video_handle_scale(struct rc_option *option, const char *arg,
		int priority);
static int video_verify_artwork(struct rc_option *option, const char *arg,
		int priority);
static int video_verify_ftr(struct rc_option *option, const char *arg, int priority);
static int video_handle_vectorres(struct rc_option *option, const char *arg,
		int priority);
static int video_verify_beam(struct rc_option *option, const char *arg,
		int priority);
static int video_verify_flicker(struct rc_option *option, const char *arg,
		int priority);
static int video_verify_intensity(struct rc_option *option, const char *arg,
		int priority);
static int video_verify_mode(struct rc_option *option, const char *arg,
		int priority);
static void update_effect(void);

struct rc_option video_opts[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
   { "Video Related",	NULL,			rc_seperator,	NULL,
     NULL,		0,			0,		NULL,
     NULL },
   { "video-mode",	"vidmod",		rc_int,		&normal_params.video_mode,
     "0",		0,			SYSDEP_DISPLAY_VIDEO_MODES-1, video_verify_mode,
     NULL },
   { "fullscreen",   	NULL,    		rc_bool,	&normal_params.fullscreen,
     "0",           	0,       		0,		NULL,
     "Select fullscreen mode (left-alt + page-down)" },
   { "arbheight",	"ah",			rc_int,		&user_yarbsize,
     "0",		0,			4096,		NULL,
     "Scale video to exactly this height (0 = disable), this overrides the heightscale and scale options" },
   { "widthscale",	"ws",			rc_int,		&user_widthscale,
     "1",		1,			8,		NULL,
     "Set X-Scale factor (increase: left-shift + insert, decrease: left-shift + delete)" },
   { "heightscale",	"hs",			rc_int,		&user_heightscale,
     "1",		1,			8,		NULL,
     "Set Y-Scale factor (increase: left-shift + home, decrease: left-shift + end)" },
   { "scale",		"s",			rc_use_function, NULL,
     NULL,		0,			0,		video_handle_scale,
     "Set X- and Y-Scale to the same factor (increase: left-shift + page-up, decrease: left-shift + page-down)" },
#ifndef DISABLE_EFFECTS
   { "effect", "ef", rc_int, &user_effect, "0", SYSDEP_DISPLAY_EFFECT_NONE, SYSDEP_DISPLAY_EFFECT_SCAN_V - 1, NULL, "Video effect:\n"
#else
   { "effect", "ef", rc_int, &user_effect, "0", SYSDEP_DISPLAY_EFFECT_NONE, SYSDEP_DISPLAY_EFFECT_NONE, NULL, "Video effect:\n"
#endif
	     "0 = none     (default)\n"
#ifndef DISABLE_EFFECTS
	     "1 = scale2x  (smooth scaling effect)\n"
	     "2 = lq2x     (low quality filter)\n"
	     "3 = hq2x     (high quality filter)\n"
	     "4 = 6tap2x   (6-tap filter with h-scanlines)\n"
	     "5 = scan2    (light scanlines)\n"
	     "6 = rgbscan  (rgb scanlines)\n"
	     "7 = scan3    (deluxe scanlines)\n"
	     "8 = fakescan (black scanlines)\n"
#endif
             "(increase: left-ctrl + page-up, decrease: left-ctrl + page-down)" },
   { "autodouble",	"adb",			rc_bool,	&use_auto_double,
     "1",		0,			0,		NULL,
     "Enable/disable automatic scale doubling for 1:2 pixel aspect ratio games" },
   { "frameskipper",	"fsr",			rc_int,		&frameskipper,
     "1",		0,			FRAMESKIP_DRIVER_COUNT-1, NULL,
     "Select which autoframeskip and throttle routines to use. Available choices are:\n0 Dos frameskip code (left-ctrl + insert)\n1 Enhanced frameskip code by William A. Barath (left-ctrl + home)" },
   { "throttle",	"th",			rc_bool,	&throttle,
     "1",		0,			0,		NULL,
     "Enable/disable throttle" },
   { "frames_to_run",	"ftr",			rc_int,		&frames_to_display,
     "0",		0,			2147483647,	video_verify_ftr,
     "Sets the number of frames to run within the game" },
   { "sleepidle",	"si",			rc_bool,	&sleep_idle,
     "1",		0,			0,		NULL,
     "Enable/disable sleep during idle" },
   { "autoframeskip",	"afs",			rc_bool,	&autoframeskip,
     "1",		0,			0,		NULL,
     "Enable/disable autoframeskip" },
   { "maxautoframeskip", "mafs",		rc_int,		&max_autoframeskip,
     "8",		0,			FRAMESKIP_LEVELS-1, NULL,
     "Set highest allowed frameskip for autoframeskip" },
   { "frameskip",	"fs",			rc_int,		&frameskip,
     "0",		0,			FRAMESKIP_LEVELS-1, NULL,
     "Set frameskip when not using autoframeskip" },
   { "brightness",	"brt",			rc_float,	&options.brightness,
     "1.0",		0.5,			2.0,		NULL,
     "Set the brightness correction (0.5 - 2.0)" },
   { "pause_brightness","pbrt",			rc_float,	&options.pause_bright,
     "0.65",		0.5,			2.0,		NULL,
     "Additional pause brightness" },
   { "gamma",		"gc",			rc_float,	&options.gamma,
     "1.0",		0.5,			2.0,		NULL,
     "Set the gamma correction (0.5 - 2.0)" },
   { "norotate",	"nr",			rc_bool,	&video_norotate,
     "0",		0,			0,		NULL,
     "Do not apply rotation" },
   { "ror",		"rr",			rc_bool,	&video_ror,
     "0",		0,			0,		NULL,
     "Rotate screen clockwise" },
   { "rol",		"rl",			rc_bool,	&video_rol,
     "0",		0,			0,		NULL,
     "Rotate screen counter-clockwise" },
   { "autoror",		NULL,			rc_bool,	&video_autoror,
     "0",		0,			0,		NULL,
     "Automatically rotate screen clockwise for vertical games" },
   { "autorol",		NULL,			rc_bool,	&video_autorol,
     "0",		0,			0,		NULL,
     "Automatically rotate screen counter-clockwise for vertical games" },
   { "flipx",		"fx",			rc_bool,	&video_flipx,
     "0",		0,			0,		NULL,
     "Flip screen left-right" },
   { "flipy",		"fy",			rc_bool,	&video_flipy,
     "0",		0,			0,		NULL,
     "Flip screen upside-down" },
   { "Use additional game artwork?", NULL,	rc_seperator,	NULL,
     NULL,		0,			0,		NULL,
     NULL },
   { "artwork",		"art",			rc_bool,	&use_artwork,
     "1",		0,			0,		video_verify_artwork,
     "Global artwork enable/disable" },
   { "use_backdrops",	"backdrop",		rc_bool,	&use_backdrops,
     "1",		0,			0,		video_verify_artwork,
     "Use backdrop artwork" },
   { "use_overlays",	"overlay",		rc_bool,	&use_overlays,
     "1",		0,			0,		video_verify_artwork,
     "Use overlay artwork" },
   { "use_bezels",	"bezel",		rc_bool,	&use_bezels,
     "1",		0,			0,		video_verify_artwork,
     "Use bezel artwork" },
   { "artwork_crop",	"artcrop",		rc_bool,	&options.artwork_crop,
     "0",		0,			0,		NULL,
     "Crop artwork to game screen only." },
   { "artwork_scale",   "artscale",		rc_int,		&options.artwork_res,
     "1",		1,			2,		NULL,
     "Artwork Scaling (1 or 2x)" },
   { "Vector Games Related", NULL,		rc_seperator,	NULL,
     NULL,		0,			0,		NULL,
     NULL },
   { "vectorres",	"vres",			rc_use_function, NULL,
     "640x480",		0,			0,		video_handle_vectorres,
     "Always scale vectorgames to XresxYres, keeping their aspect ratio. This overrides the scale options" },
   { "beam", "B", rc_float, &f_beam, "1.0", 1.0, 16.0, video_verify_beam, "Set the beam size for vector games" },
   { "flicker", "f", rc_float, &f_flicker, "0.0", 0.0, 100.0, video_verify_flicker, "Set the flicker for vector games" },
   { "intensity", NULL, rc_float, &f_intensity, "1.5", 0.5, 3.0, video_verify_intensity, "Set intensity in vector games" },
   { "antialias",	"aa",			rc_bool,	&options.antialias,
     "1",		0,			0,		NULL,
     "Enable/disable antialiasing" },
   { "translucency",	"t",			rc_bool,	&options.translucency,
     "1",		0,			0,		NULL,
     "Enable/disable tranlucency" },
   { "hardware-vectors", "hwvec",		rc_int,		&use_hw_vectors,
     "1",		0,			2,		NULL,
     "Use the video card to draw the vectors in vector games:\n0 never\n1 auto\n2 always" },
   { "mngwrite", NULL, rc_string, &mngwrite, NULL, 0, 0, NULL, "Save video in specified mng file" },
   { NULL,		NULL,			rc_link,	sysdep_display_opts,
     NULL,		0,			0,		NULL,
     NULL },
   { NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

static int video_verify_mode(struct rc_option *option, const char *arg,
		int priority)
{
  const char *hotkey[] = {
    "insert",
    "home",
    "page-up",
    "delete",
    "end"
  };
  static char help_buf[1024];
  
  if (!option->help)
  {
    char *dest = help_buf;
    int bufsize = 1024;
    int i,n;

    n = snprintf(dest, bufsize, "Select video mode:");
    dest    += n;
    bufsize -= n;
    for (i=0;i<SYSDEP_DISPLAY_VIDEO_MODES;i++)
    {
      /* mode available */
      if(sysdep_display_properties.mode_info[i])
      {
        n = snprintf(dest, bufsize, "\n%d = %s (left-alt + %s)",
          i, sysdep_display_properties.mode_name[i], hotkey[i]);
        if ((n < 0) || (n >= (bufsize-1)))
          break;
        dest    += n;
        bufsize -= n;
      }
    }
    option->help = help_buf;
  }
  
  if(!sysdep_display_properties.mode_info[normal_params.video_mode])
  {
    fprintf(stderr, "Error: video mode %d is not available\n",
      normal_params.video_mode);
    return 1;
  }

  option->priority = priority;

  return 0;
}

static int video_handle_scale(struct rc_option *option, const char *arg,
   int priority)
{
	if (rc_set_option2(video_opts, "widthscale", arg, priority))
		return -1;
	if (rc_set_option2(video_opts, "heightscale", arg, priority))
		return -1;

	option->priority = priority;

	return 0;
}

static int video_verify_artwork(struct rc_option *option, const char *arg,
		int priority)
{
	/* set the artwork options */
	if (use_artwork)
	{
		options.use_artwork = ARTWORK_USE_ALL;
		if (use_backdrops == 0)
			options.use_artwork &= ~ARTWORK_USE_BACKDROPS;
		if (use_overlays == 0)
			options.use_artwork &= ~ARTWORK_USE_OVERLAYS;
		if (use_bezels == 0)
			options.use_artwork &= ~ARTWORK_USE_BEZELS;
	}
	else
		options.use_artwork = ARTWORK_USE_NONE;

	option->priority = priority;
	return 0;
}

static int video_verify_ftr(struct rc_option *option, const char *arg, int priority)
{
	int ftr;

	if (sscanf(arg, "%d", &ftr) != 1)
	{
		fprintf(stderr, "error: invalid value for frames_to_run: %s\n", arg);
		return -1;
	}

	/* if we're running < 5 minutes, allow us to skip warnings to facilitate benchmarking/validation testing */
	frames_to_display = ftr;
	if (frames_to_display > 0 && frames_to_display < 60*60*5)
		options.skip_warnings = options.skip_gameinfo = options.skip_disclaimer = 1;

	option->priority = priority;
	return 0;
}

static int video_handle_vectorres(struct rc_option *option, const char *arg,
   int priority)
{
	if (sscanf(arg, "%dx%d", &options.vector_width, &options.vector_height) != 2)
	{
		fprintf(stderr, "error: invalid value for vectorres: %s\n", arg);
		return -1;
	}

	option->priority = priority;

	return 0;
}

static int video_verify_beam(struct rc_option *option, const char *arg,
		int priority)
{
	options.beam = (int)(f_beam * 0x00010000);
	if (options.beam < 0x00010000)
		options.beam = 0x00010000;
	else if (options.beam > 0x00100000)
		options.beam = 0x00100000;

	option->priority = priority;

	return 0;
}

static int video_verify_flicker(struct rc_option *option, const char *arg,
		int priority)
{
	options.vector_flicker = (int)(f_flicker * 2.55);
	if (options.vector_flicker < 0)
		options.vector_flicker = 0;
	else if (options.vector_flicker > 255)
		options.vector_flicker = 255;

	option->priority = priority;

	return 0;
}

static int video_verify_intensity(struct rc_option *option, const char *arg,
		int priority)
{
	options.vector_intensity = f_intensity;
	option->priority = priority;
	return 0;
}

int osd_create_display(const osd_create_params *params,
		UINT32 *rgb_components)
{
	int orientation;
	const game_driver *clone_of;

	video_fps                      = params->fps;
	normal_params.width            = params->width;
	normal_params.height           = params->height;
	normal_params.depth            = params->depth;
	normal_params.max_width        = params->width;
	normal_params.max_height       = params->height;
	normal_params.title            = title;
	normal_params.aspect_ratio     = (double)params->aspect_x/params->aspect_y;
	normal_params.keyboard_handler = xmame_keyboard_register_event;
	normal_params.vec_src_bounds   = NULL;
	normal_params.vec_dest_bounds  = NULL;

	/* get the orientation, start with the game's built-in orientation */
	orientation = drivers[game_index]->flags & ORIENTATION_MASK;

	/* override if no rotation requested */
	if (video_norotate)
		orientation = ROT0;

	/* rotate right */
	if (video_ror)
	{
		/* if only one of the components is inverted, switch them */
		if ((orientation & ROT180) == ORIENTATION_FLIP_X ||
				(orientation & ROT180) == ORIENTATION_FLIP_Y)
			orientation ^= ROT180;

		orientation ^= ROT90;
	}

	/* rotate left */
	if (video_rol)
	{
		/* if only one of the components is inverted, switch them */
		if ((orientation & ROT180) == ORIENTATION_FLIP_X ||
				(orientation & ROT180) == ORIENTATION_FLIP_Y)
			orientation ^= ROT180;

		orientation ^= ROT270;
	}

	/* auto-rotate right (e.g. for rotating lcds), based on original orientation */
	if (video_autoror && (drivers[game_index]->flags & ORIENTATION_SWAP_XY))
	{
		/* if only one of the components is inverted, switch them */
		if ((orientation & ROT180) == ORIENTATION_FLIP_X ||
				(orientation & ROT180) == ORIENTATION_FLIP_Y)
			orientation ^= ROT180;

		orientation ^= ROT90;
	}

	/* auto-rotate left (e.g. for rotating lcds), based on original orientation */
	if (video_autorol && (drivers[game_index]->flags & ORIENTATION_SWAP_XY))
	{
		/* if only one of the components is inverted, switch them */
		if ((orientation & ROT180) == ORIENTATION_FLIP_X ||
				(orientation & ROT180) == ORIENTATION_FLIP_Y)
			orientation ^= ROT180;

		orientation ^= ROT270;
	}

	/* flip X/Y */
	if (video_flipx)
		orientation ^= ORIENTATION_FLIP_X;
	if (video_flipy)
		orientation ^= ORIENTATION_FLIP_Y;

	normal_params.orientation = 0;
	if (orientation & ORIENTATION_FLIP_X)
		normal_params.orientation |= SYSDEP_DISPLAY_FLIPX;
	if (orientation & ORIENTATION_FLIP_Y)
		normal_params.orientation |= SYSDEP_DISPLAY_FLIPY;
	if (orientation & ORIENTATION_SWAP_XY)
		normal_params.orientation |= SYSDEP_DISPLAY_SWAPXY;

	/* Setup width- and height-scale */
	if (user_yarbsize)
	{
		if (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY)
			user_heightscale = (double)user_yarbsize/params->width + 0.5;
		else
			user_heightscale = (double)user_yarbsize/params->height + 0.5;
	}
	else if (use_auto_double && (user_widthscale == user_heightscale))
	{
		if ((params->video_attributes & VIDEO_PIXEL_ASPECT_RATIO_MASK)
				== VIDEO_PIXEL_ASPECT_RATIO_1_2)
		{
			if (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY)
				user_widthscale *= 2;
			else
				user_heightscale *= 2;
		}

		if ((params->video_attributes & VIDEO_PIXEL_ASPECT_RATIO_MASK)
				== VIDEO_PIXEL_ASPECT_RATIO_2_1)
		{
			if (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY)
				user_heightscale *= 2;
			else
				user_widthscale *= 2;
		}
	}
	/* Verify current usersettings versus effect and try to keep aspect. */
	update_effect();
	/* Update usersettings with definitive results. */
	user_widthscale  = normal_params.widthscale;
	user_heightscale = normal_params.heightscale;
	user_yarbsize    = normal_params.yarbsize;

	switch (use_hw_vectors)
	{
		case 0: /* disabled */
			break;
		case 1: /* auto */
			if (artwork_overlay_active())
				break;
		case 2: /* always on */
			if (params->video_attributes & VIDEO_TYPE_VECTOR)
			{
				normal_params.vec_src_bounds  = &(Machine->visible_area);
				normal_params.vec_dest_bounds = artwork_get_game_rect();
			}
	}

	if (sysdep_display_open(&normal_params) != OSD_OK)
		return -1;

	if (normal_params.vec_src_bounds)
		vector_register_aux_renderer(sysdep_display_properties.vector_renderer);

	if (!(normal_palette = sysdep_palette_create(&sysdep_display_properties.palette_info, normal_params.depth)))
		return -1;

	/* a lot of display_targets need to have the display initialised before
	   initialising any input devices */
	if (osd_input_initpost() != OSD_OK)
		return -1;

	/* fill in the resulting RGB components */
	if (rgb_components)
	{
		if (params->depth == 32)
		{
			rgb_components[0] = (0xff << 16) | (0x00 << 8) | 0x00;
			rgb_components[1] = (0x00 << 16) | (0xff << 8) | 0x00;
			rgb_components[2] = (0x00 << 16) | (0x00 << 8) | 0xff;
		}
		else
		{
			rgb_components[0] = 0x7c00;
			rgb_components[1] = 0x03e0;
			rgb_components[2] = 0x001f;
		}
	}

	/* setup debugger related stuff */
	debug_params.width      = options.debug_width;
	debug_params.height     = options.debug_height;
	debug_params.max_width  = options.debug_width;
	debug_params.max_height = options.debug_height;

	/* apply vis area override hacks */
	if ((clone_of = driver_get_clone(drivers[game_index])) && !strcmp(clone_of->name, "megatech"))
	{
		game_vis_area_override_rect[1].min_y = 192;
		game_vis_area_override_rect[2].max_x = 255;
		game_vis_area_override_rect[2].max_y = 191;
		game_vis_area_override_aspect[1] = (double)4.0/3.0;
		game_vis_area_override_aspect[2] = (double)4.0/3.0;
		game_vis_area_override_index = 1;
	}
	if ((clone_of = driver_get_clone(drivers[game_index])) && !strcmp(clone_of->name, "playch10"))
	{
		game_vis_area_override_rect[1].min_y = 240;
		game_vis_area_override_rect[2].max_y = 239;
		game_vis_area_override_aspect[1] = (double)4.0/3.0;
		game_vis_area_override_aspect[2] = (double)4.0/3.0;
		game_vis_area_override_index = 1;
	}
	if (!strcmp(drivers[game_index]->name, "punchout"))
	{
		game_vis_area_override_rect[1].min_y = 224;
		game_vis_area_override_rect[2].max_y = 223;
		game_vis_area_override_aspect[1] = (double)4.0/3.0;
		game_vis_area_override_aspect[2] = (double)4.0/3.0;
	}
	if (game_vis_area_override_rect[1].min_y != -1)
	{
		game_vis_area_override_aspect[0] = normal_params.aspect_ratio;
		status_msg  = "Dual monitor Game, press\nleft-ctrl+left-shift+insert\nto toggle visible monitors";
		show_status = 5.0 * video_fps;
		ui_show_fps_temp(5.0);
	}

	if (mngwrite != NULL)
		record_movie_start(mngwrite);

	return 0;
}

void osd_close_display(void)
{
	if (normal_palette)
	{
		sysdep_palette_destroy(normal_palette);
		normal_palette = NULL;
	}

	if (debug_palette)
	{
		sysdep_palette_destroy(debug_palette);
		debug_palette = NULL;
	}
	sysdep_display_close();

	/* print a final result to the stdout */
	if (frames_displayed != 0)
	{
		cycles_t cps = osd_cycles_per_second();
		fprintf(stderr_file, "Average FPS: %f (%d frames)\n", (double)cps / (end_time - start_time) * frames_displayed, frames_displayed);
	}
}

#define X_SCALING_CHANGED      	   0x01
#define Y_SCALING_CHANGED      	   0x02
#define EFFECT_CHANGED             0x04
#define VIDMODE_FULLSCREEN_CHANGED 0x08
#define VISIBLE_AREA_CHANGED       0x10

static void update_params(void)
{
  int retval;
  int requested_widthscale  = normal_params.widthscale;
  int requested_heightscale = normal_params.heightscale;
#ifdef x11
  int sound_disabled = 0;
  
  /* Close sound, DGA (fork) makes the filehandle open twice,
     so closing it here and re-openeing after the transition
     fixes that.	   -- Steve bpk@hoopajoo.net */
  if ((normal_params_changed & VIDMODE_FULLSCREEN_CHANGED) &&
      (normal_params.video_mode == 0) &&
      (normal_params.fullscreen == 1))
  {
    osd_sound_enable( 0 );
    sound_disabled = 1;
  }
#endif

  retval = sysdep_display_change_params(&normal_params);
  
  if (retval & SYSDEP_DISPLAY_PROPERTIES_CHANGED)
  {
	if (normal_palette)
	{
		sysdep_palette_destroy(normal_palette);
		normal_palette = NULL;
	}

	if (normal_params.vec_src_bounds)
	{
		/* we could have switched between hw and sw drawn vectors,
		   so clear Machine->scrbitmap and don't use vector_dirty_pixels
		   for the next (not skipped) frame */
		schedule_full_refresh();
		vector_register_aux_renderer(sysdep_display_properties.vector_renderer);
	}
  }

  /* If we've tried to change the scaling and we've succeeded update the user
     scale settings */
  if ( ((normal_params_changed & X_SCALING_CHANGED) &&
        (requested_widthscale == normal_params.widthscale)) ||
       ((normal_params_changed & Y_SCALING_CHANGED) &&
        (requested_heightscale == normal_params.heightscale)) )
  {
    user_widthscale  = normal_params.widthscale;
    user_heightscale = normal_params.heightscale;
    user_yarbsize    = normal_params.yarbsize;
  }

  if ((normal_params_changed & (X_SCALING_CHANGED |
        Y_SCALING_CHANGED | EFFECT_CHANGED)) ||
      (retval & SYSDEP_DISPLAY_SCALING_EFFECT_CHANGED))
  {
    show_effect_or_scale = 2.0 * video_fps;
    ui_show_fps_temp(2.0);
  }
  
  if ((normal_params_changed & VIDMODE_FULLSCREEN_CHANGED) ||
      (retval & SYSDEP_DISPLAY_VIDMODE_FULLSCREEN_CHANGED))
  {
    status_msg  = sysdep_display_properties.mode_name[normal_params.video_mode];
    show_status = 2.0 * video_fps;
    ui_show_fps_temp(2.0);
  }

#ifdef x11
  /* Re-enable sound */
  if (sound_disabled)
    osd_sound_enable( 1 );
#endif

  normal_params_changed = 0;
}

static void update_palette(mame_display *display, int force_dirty)
{
	int i, j;

	/* loop over dirty colors in batches of 32 */
	for (i = 0; i < display->game_palette_entries; i += 32)
	{
		UINT32 dirtyflags = display->game_palette_dirty[i / 32];
		if (dirtyflags || force_dirty)
		{
			display->game_palette_dirty[i / 32] = 0;

			/* loop over all 32 bits and update dirty entries */
			for (j = 0; (j < 32) && (i + j < display->game_palette_entries); j++, dirtyflags >>= 1)
				if (((dirtyflags & 1) || force_dirty) && (i + j < display->game_palette_entries))
				{
					/* extract the RGB values */
					rgb_t rgbvalue = display->game_palette[i + j];
					int r = RGB_RED(rgbvalue);
					int g = RGB_GREEN(rgbvalue);
					int b = RGB_BLUE(rgbvalue);
					
					/* fprintf(stderr,
					  "Setting pen: %d to: r:%d,g:%d,b:%d\n",
                                          i + j, r, g, b); */

					sysdep_palette_set_pen(normal_palette,
							i + j, r, g, b);
				}
		}
	}
}

static void update_debug_display(mame_display *display)
{
	rectangle vis_area;
	rectangle dirty_area;

	if (!debug_palette)
	{
		int  i, r, g, b;
		debug_palette = sysdep_palette_create(&sysdep_display_properties.palette_info, 16);
		if (!debug_palette)
		{
			/* oops this sorta sucks */
			fprintf(stderr_file, "Argh, creating the palette failed (out of memory?) aborting\n");
			sysdep_display_close();
			exit(1);
		}

		/* Initialize the lookup table for the debug palette. */
		for (i = 0; i < DEBUGGER_TOTAL_COLORS; i++)
		{
			/* extract the RGB values */
			rgb_t rgbvalue = display->debug_palette[i];
			r = RGB_RED(rgbvalue);
			g = RGB_GREEN(rgbvalue);
			b = RGB_BLUE(rgbvalue);

			sysdep_palette_set_pen(debug_palette,
					i, r, g, b);
		}
	}

	vis_area.min_x   = 0;
	vis_area.max_x   = options.debug_width - 1;
	vis_area.min_y   = 0;
	vis_area.max_y   = options.debug_height - 1;
	dirty_area.min_x = 0;
	dirty_area.max_x = options.debug_width - 1;
	dirty_area.min_y = 0;
	dirty_area.max_y = options.debug_height - 1;
	sysdep_display_update(display->debug_bitmap, &vis_area,
			&dirty_area, debug_palette, 0, 0);
}

static void update_effect(void)
{
  /* Try to get the user set scale factors */
  normal_params.widthscale  = user_widthscale;
  normal_params.heightscale = user_heightscale;
  normal_params.yarbsize    = user_yarbsize;
  if ( (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY) &&
       (user_effect >= SYSDEP_DISPLAY_EFFECT_SCAN_H) )
    normal_params.effect = user_effect + SYSDEP_DISPLAY_EFFECT_SCAN_V -
      SYSDEP_DISPLAY_EFFECT_SCAN_H;
  else
    normal_params.effect = user_effect;

  sysdep_display_check_effect_params(&normal_params);
  
  /* if we didn't get the requested widthscale, clear yarbsize
     (and thus try to keep the aspect the next step */
  if (user_widthscale != normal_params.widthscale)
    normal_params.yarbsize = 0;
  
  /* attempt to keep the same aspect */
  if ( (normal_params.yarbsize == 0) &&
       ((double)normal_params.widthscale/normal_params.heightscale) !=
       ((double)user_widthscale/user_heightscale) )
  {
    if ((sysdep_display_effect_properties[normal_params.effect].flags &
         SYSDEP_DISPLAY_X_SCALE_LOCKED) ||
        (!(sysdep_display_effect_properties[normal_params.effect].flags &
           SYSDEP_DISPLAY_Y_SCALE_LOCKED) && 
         (normal_params.widthscale != user_widthscale)))
    {
      normal_params.heightscale = normal_params.widthscale
        / ((double)user_widthscale/user_heightscale) + 0.5;
    }
    else
    {
      normal_params.widthscale = normal_params.heightscale
        * ((double)user_widthscale/user_heightscale) + 0.5;
    }
  }
}

static void update_game_vis_area(void)
{
  if (game_vis_area_override_rect[game_vis_area_override_index].min_x != -1)
    game_vis_area.min_x =
      game_vis_area_override_rect[game_vis_area_override_index].min_x;

  if (game_vis_area_override_rect[game_vis_area_override_index].min_y != -1)
    game_vis_area.min_y =
      game_vis_area_override_rect[game_vis_area_override_index].min_y;

  if (game_vis_area_override_rect[game_vis_area_override_index].max_x != -1)
    game_vis_area.max_x =
      game_vis_area_override_rect[game_vis_area_override_index].max_x;

  if (game_vis_area_override_rect[game_vis_area_override_index].max_y != -1)
    game_vis_area.max_y =
      game_vis_area_override_rect[game_vis_area_override_index].max_y;
      
  if (!(game_vis_area_override_aspect[game_vis_area_override_index] < 0.0))
    normal_params.aspect_ratio =
      game_vis_area_override_aspect[game_vis_area_override_index];

  normal_params.width  = (game_vis_area.max_x + 1) - game_vis_area.min_x;
  normal_params.height = (game_vis_area.max_y + 1) - game_vis_area.min_y;
		   
  ui_set_visible_area(game_vis_area.min_x, game_vis_area.min_y,
    game_vis_area.max_x, game_vis_area.max_y);

  normal_params_changed |= VISIBLE_AREA_CHANGED;
}

static int skip_next_frame = 0;

typedef int (*skip_next_frame_func)(void);
static skip_next_frame_func skip_next_frame_functions[FRAMESKIP_DRIVER_COUNT] =
{
	dos_skip_next_frame,
	barath_skip_next_frame
};

typedef int (*show_fps_frame_func)(char *buffer);
static show_fps_frame_func show_fps_frame_functions[FRAMESKIP_DRIVER_COUNT] =
{
	dos_show_fps,
	barath_show_fps
};

int osd_skip_this_frame(void)
{
	return skip_next_frame;
}

int osd_get_frameskip(void)
{
	return autoframeskip ? -(frameskip + 1) : frameskip;
}

void change_debugger_focus(int new_debugger_focus)
{
	if (debugger_has_focus != new_debugger_focus)
	{
		debugger_has_focus = new_debugger_focus;
		if (new_debugger_focus)
		{
			if((sysdep_display_change_params(&debug_params) &
						SYSDEP_DISPLAY_PROPERTIES_CHANGED) &&
					normal_palette)
			{
				sysdep_palette_destroy(normal_palette);
				normal_palette = NULL;
			}
		}
		else
			normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
	}
}

/* Update the display. */
void osd_update_video_and_audio(mame_display *display)
{
	cycles_t curr;
	const char *msg = NULL;
	static int flags = 0;
	static int palette_changed = 0;

#ifdef MESS
	if (!throttle && (display->changed_flags & GAME_OPTIONAL_FRAMESKIP))
		display->changed_flags &= ~GAME_VISIBLE_AREA_CHANGED;
#endif
	
	/*** STEP 1 update sound,fps,vis_area,palette and leds ***/
	if (sysdep_sound_stream)
	{
		sysdep_sound_stream_update(sysdep_sound_stream);
	}
	if (display->changed_flags & GAME_REFRESH_RATE_CHANGED)
	{
		video_fps = display->game_refresh_rate;
		sound_update_refresh_rate(display->game_refresh_rate);
	}
	if (display->changed_flags & GAME_VISIBLE_AREA_CHANGED)
	{
	  game_vis_area = display->game_visible_area;
          update_game_vis_area();
	}
	if ((display->changed_flags & GAME_PALETTE_CHANGED))
		palette_changed = 1;
	
	/*** STEP 2: determine if the debugger or the normal game window
	     should be shown ***/
	if (display->changed_flags & DEBUG_FOCUS_CHANGED)
		change_debugger_focus(display->debug_focus);
	/* If the user presses the F5 key, toggle the debugger's focus */
	else if (input_ui_pressed(IPT_UI_TOGGLE_DEBUG) && Machine->debug_mode)
		change_debugger_focus(!debugger_has_focus);

	/*** STEP 3: update the focused display ***/
	if (debugger_has_focus)
	{
		if (display->changed_flags & DEBUG_BITMAP_CHANGED)
			update_debug_display(display);
	}
	else
	{
#ifdef MESS
		if (((Machine->gamedrv->flags & GAME_COMPUTER) == 0) || mess_ui_active())
#endif
		{
			if (code_pressed(KEYCODE_LALT) &&
					code_pressed(KEYCODE_LCONTROL))
			{
				if (code_pressed_memory(KEYCODE_INSERT))
					flags |= SYSDEP_DISPLAY_HOTKEY_OPTION0;
				if (code_pressed_memory(KEYCODE_HOME))
					flags |= SYSDEP_DISPLAY_HOTKEY_OPTION1;
				if (code_pressed_memory(KEYCODE_PGUP))
					flags |= SYSDEP_DISPLAY_HOTKEY_OPTION2;
				if (code_pressed_memory(KEYCODE_END))
					flags |= SYSDEP_DISPLAY_HOTKEY_OPTION3;
				if (code_pressed_memory(KEYCODE_PGDN))
					flags |= SYSDEP_DISPLAY_HOTKEY_OPTION4;
			}
			else if (code_pressed(KEYCODE_LSHIFT) &&
					code_pressed(KEYCODE_LCONTROL))
			{
				if (code_pressed_memory(KEYCODE_INSERT))
				{
					game_vis_area_override_index++;
					if(game_vis_area_override_index>2)
						game_vis_area_override_index = 0;
					game_vis_area = display->game_visible_area;
					update_game_vis_area();
				}
			}
			else if (code_pressed(KEYCODE_LALT))
			{
				if (code_pressed_memory(KEYCODE_INSERT))
				{
					normal_params.video_mode = 0;
					normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
				}
				if (code_pressed_memory(KEYCODE_HOME))
				{
					normal_params.video_mode = 1;
					normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
				}
				if (code_pressed_memory(KEYCODE_PGUP))
				{
					normal_params.video_mode = 2;
					normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
				}
				if (code_pressed_memory(KEYCODE_DEL))
				{
					normal_params.video_mode = 3;
					normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
				}
				if (code_pressed_memory(KEYCODE_END))
				{
					normal_params.video_mode = 4;
					normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
				}
				if (code_pressed_memory(KEYCODE_PGDN))
				{
					normal_params.fullscreen = 1 - normal_params.fullscreen;
					normal_params_changed |= VIDMODE_FULLSCREEN_CHANGED;
				}
			}
			else if (code_pressed(KEYCODE_LCONTROL))
			{
				int effect_mod = 0;
				if (code_pressed_memory(KEYCODE_INSERT))
					frameskipper = 0;
				if (code_pressed_memory(KEYCODE_HOME))
					frameskipper = 1;
				if (code_pressed_memory(KEYCODE_DEL))
					flags |= SYSDEP_DISPLAY_HOTKEY_GRABMOUSE;
				if (code_pressed_memory(KEYCODE_END))
					flags |= SYSDEP_DISPLAY_HOTKEY_GRABKEYB;
#ifndef DISABLE_EFFECTS
				if (code_pressed_memory(KEYCODE_PGUP))
					effect_mod = 1;
				if (code_pressed_memory(KEYCODE_PGDN))
					effect_mod = -1;
#endif
				if (effect_mod && (sysdep_display_properties.mode_info[
							normal_params.video_mode] & SYSDEP_DISPLAY_EFFECTS))
				{
					int i=0, scaled_width, scaled_height;

					/* check if the effect fits the screen */
					do
					{
						if (!(i&1)) /* 1st try, 3rd try, etc: next effect */
						{
							/* next effect */
							user_effect += effect_mod;
							if (user_effect < 0)
								user_effect = SYSDEP_DISPLAY_EFFECT_SCAN_V-1;
							if (user_effect >= SYSDEP_DISPLAY_EFFECT_SCAN_V)
								user_effect = 0;

							update_effect();
						}
						else /* 2nd try, 4th try... same effect... */
						{
							normal_params.widthscale  = 1;
							normal_params.heightscale = 1;
							normal_params.yarbsize    = 0;
						}

						/* is this going to fit? */
						sysdep_display_check_effect_params(&normal_params);
						if (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY)
						{
							scaled_width  = normal_params.height * normal_params.widthscale;
							scaled_height = normal_params.yarbsize? normal_params.yarbsize:
								normal_params.width * normal_params.heightscale;
						}
						else
						{
							scaled_width  = normal_params.width * normal_params.widthscale;
							scaled_height = normal_params.yarbsize? normal_params.yarbsize:
								normal_params.height * normal_params.heightscale;
						}
						i++;
					} while ((i <= (2*SYSDEP_DISPLAY_EFFECT_LAST)) &&
							((scaled_width  > sysdep_display_properties.max_width ) ||
							 (scaled_height > sysdep_display_properties.max_height)));

					normal_params_changed |= EFFECT_CHANGED;
				}
			}
			else if (code_pressed(KEYCODE_LSHIFT))
			{
				int widthscale_mod  = 0;
				int heightscale_mod = 0;
				int scale_mod = 0;

				if (code_pressed_memory(KEYCODE_INSERT))
					widthscale_mod = 1;
				if (code_pressed_memory(KEYCODE_DEL))
					widthscale_mod = -1;
				if (code_pressed_memory(KEYCODE_HOME))
					heightscale_mod = 1;
				if (code_pressed_memory(KEYCODE_END))
					heightscale_mod = -1;
				if (code_pressed_memory(KEYCODE_PGUP))
					scale_mod = 1;
				if (code_pressed_memory(KEYCODE_PGDN))
					scale_mod = -1;
				if (scale_mod)
				{
					if (normal_params.widthscale == normal_params.heightscale)
					{
						normal_params.widthscale  += scale_mod;
						normal_params.heightscale += scale_mod;
					}
					else if (normal_params.widthscale == 
							(2*normal_params.heightscale))
					{
						normal_params.widthscale  += 2*scale_mod;
						normal_params.heightscale += scale_mod;
					}
					else if (normal_params.heightscale == 
							(2*normal_params.widthscale))
					{
						normal_params.widthscale  += scale_mod;
						normal_params.heightscale += 2*scale_mod;
					}
					else
					{
						normal_params.widthscale  += scale_mod *
							normal_params.widthscale;
						normal_params.heightscale += scale_mod *
							normal_params.heightscale;
					}
					normal_params_changed |= X_SCALING_CHANGED|Y_SCALING_CHANGED;
					sysdep_display_check_effect_params(&normal_params);
				}
				if (widthscale_mod)
				{
					normal_params.widthscale += widthscale_mod;
					normal_params_changed |= X_SCALING_CHANGED;
					sysdep_display_check_effect_params(&normal_params);
				}
				if (heightscale_mod)
				{
					normal_params.heightscale += heightscale_mod;
					normal_params.yarbsize = 0;
					normal_params_changed |= Y_SCALING_CHANGED;
					sysdep_display_check_effect_params(&normal_params);
				}
			}
		}

		/* determine non hotkey flags */
		if (ui_is_dirty())
			flags |= SYSDEP_DISPLAY_UI_DIRTY;

		if (display->changed_flags & GAME_BITMAP_CHANGED)
		{
			rectangle vis_area = game_vis_area;

			/* at the end, we need the current time */
			curr = osd_cycles();

			/* update stats for the FPS average calculation */
			if (start_time == 0)
			{
				/* start the timer going 1 second into the game */
				if (timer_get_time() > 1.0)
					start_time = curr;
			}
			else
			{
				frames_displayed++;
				if (frames_displayed == frames_to_display)
				{
					char name[20];
					mame_file *fp;

					/* make a filename with an underscore prefix */
					sprintf(name, "_%.8s", Machine->gamedrv->name);

					/* write out the screenshot */
					if ((fp = mame_fopen(Machine->gamedrv->name, name, FILETYPE_SCREENSHOT, 1)) != NULL)
					{
						save_screen_snapshot_as(fp, artwork_get_ui_bitmap());
						mame_fclose(fp);
					}
					mame_schedule_exit();
				}
				end_time = curr;
			}

			if (normal_params_changed)
				update_params();

			if (!normal_palette)
			{
				/* the palette had been destroyed because of display changes */
				normal_palette = sysdep_palette_create(&sysdep_display_properties.palette_info, normal_params.depth);
				if (!normal_palette)
				{
					/* oops this sorta sucks */
					fprintf(stderr_file, "Argh, creating the palette failed (out of memory?) aborting\n");
					sysdep_display_close();
					sysdep_display_exit();
					exit(1);
				}
				update_palette(display, 1);
				palette_changed = 0;
			}

			if (palette_changed)
			{
				update_palette(display, 0);
				palette_changed = 0;
			}

			profiler_mark(PROFILER_BLIT);
			/* update and check if the display properties were changed */
			msg = sysdep_display_update(display->game_bitmap,
					&vis_area, &(display->game_bitmap_update),
					normal_palette, display->led_state, flags);
			profiler_mark(PROFILER_END);
			if (msg)
			{
				status_msg  = msg;
				show_status = 2.0 * display->game_refresh_rate;
				ui_show_fps_temp(2.0);
			}
			flags = 0;
		}
	}

	/*** STEP 4: handle frameskip ***/
	if (input_ui_pressed(IPT_UI_FRAMESKIP_INC))
	{
		/* if autoframeskip, disable auto and go to 0 */
		if (autoframeskip)
		{
			autoframeskip = 0;
			frameskip = 0;
		}

		/* wrap from maximum to auto */
		else if (frameskip == FRAMESKIP_LEVELS - 1)
		{
			frameskip = 0;
			autoframeskip = 1;
		}

		/* else just increment */
		else
			frameskip++;

		/* display the FPS counter for 2 seconds */
		ui_show_fps_temp(2.0);

		/* reset the frame counter so we'll measure the average FPS on a consistent status */
		frames_displayed = 0;
	}
	if (input_ui_pressed(IPT_UI_FRAMESKIP_DEC))
	{
		/* if autoframeskip, disable auto and go to max */
		if (autoframeskip)
		{
			autoframeskip = 0;
			frameskip = FRAMESKIP_LEVELS-1;
		}

		/* wrap from 0 to auto */
		else if (frameskip == 0)
			autoframeskip = 1;

		/* else just decrement */
		else
			frameskip--;

		/* display the FPS counter for 2 seconds */
		ui_show_fps_temp(2.0);

		/* reset the frame counter so we'll measure the average FPS on a consistent status */
		frames_displayed = 0;
	}
	if (input_ui_pressed(IPT_UI_THROTTLE))
	{
		if (!code_pressed(KEYCODE_LSHIFT) && !code_pressed(KEYCODE_RSHIFT))
		{
			throttle ^= 1;

			/*
			 * reset the frame counter so we'll measure the average
			 * FPS on a consistent status
			 */
			frames_displayed = 0;
		}
		else
			sleep_idle ^= 1;
	}
	skip_next_frame = (*skip_next_frame_functions[frameskipper])();
	
	/* this needs to be called every frame, so do this here */
	osd_poll_joysticks();
}

mame_bitmap *osd_override_snapshot(mame_bitmap *bitmap,
		rectangle *bounds)
{
	rectangle newbounds;
	mame_bitmap *copy;
	int x, y, w, h, t;

	/* if we can send it in raw, no need to override anything */
	if (!(normal_params.orientation & SYSDEP_DISPLAY_SWAPXY) && !(normal_params.orientation & SYSDEP_DISPLAY_FLIPX) && !(normal_params.orientation & SYSDEP_DISPLAY_FLIPY))
		return NULL;

	/* allocate a copy */
	w = (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY) ? bitmap->height : bitmap->width;
	h = (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY) ? bitmap->width : bitmap->height;
	copy = bitmap_alloc_depth(w, h, bitmap->depth);
	if (!copy)
		return NULL;

	/* populate the copy */
	for (y = bounds->min_y; y <= bounds->max_y; y++)
		for (x = bounds->min_x; x <= bounds->max_x; x++)
		{
			int tx = x, ty = y;

			/* apply the rotation/flipping */
			if ((normal_params.orientation & SYSDEP_DISPLAY_SWAPXY))
			{
				t = tx; tx = ty; ty = t;
			}
			if ((normal_params.orientation & SYSDEP_DISPLAY_FLIPX))
				tx = copy->width - tx - 1;
			if ((normal_params.orientation & SYSDEP_DISPLAY_FLIPY))
				ty = copy->height - ty - 1;

			/* read the old pixel and copy to the new location */
			switch (copy->depth)
			{
				case 15:
				case 16:
					*((UINT16 *)copy->base + ty * copy->rowpixels + tx) =
						*((UINT16 *)bitmap->base + y * bitmap->rowpixels + x);
					break;

				case 32:
					*((UINT32 *)copy->base + ty * copy->rowpixels + tx) =
						*((UINT32 *)bitmap->base + y * bitmap->rowpixels + x);
					break;
			}
		}

	/* compute the oriented bounds */
	newbounds = *bounds;

	/* apply X/Y swap first */
	if (normal_params.orientation & SYSDEP_DISPLAY_SWAPXY)
	{
		t = newbounds.min_x; newbounds.min_x = newbounds.min_y; newbounds.min_y = t;
		t = newbounds.max_x; newbounds.max_x = newbounds.max_y; newbounds.max_y = t;
	}

	/* apply X flip */
	if (normal_params.orientation & SYSDEP_DISPLAY_FLIPX)
	{
		t = copy->width - newbounds.min_x - 1;
		newbounds.min_x = copy->width - newbounds.max_x - 1;
		newbounds.max_x = t;
	}

	/* apply Y flip */
	if (normal_params.orientation & SYSDEP_DISPLAY_FLIPY)
	{
		t = copy->height - newbounds.min_y - 1;
		newbounds.min_y = copy->height - newbounds.max_y - 1;
		newbounds.max_y = t;
	}

	*bounds = newbounds;
	return copy;
}

/* Note there are 3 known different variants of snprintf:
 1 returns -1 when the buffer was to small
 2 returns the length which would have beem written if the
   buffer was big enough.
 3 returns the number of chars written, you can try to detect
   if the buffer was to small by seeing if that this is one less
   then the sizeof the buffer. */
const char *osd_get_fps_text(const performance_info *performance)
{
	static char buffer[1024];
	char *dest  = buffer;
	int bufsize = 1024;
	int i       = (*show_fps_frame_functions[frameskipper])(dest);

	if (!i)
	{
	  /* display the FPS, frameskip, percent, fps and target fps */
	  i = snprintf(dest, bufsize, "%s%s%s%2d%4d%%%4d/%d fps",
	    throttle ? "T " : "",
	    (throttle && sleep_idle) ? "S " : "",
	    autoframeskip ? "auto" : "fskp", frameskip,
	    (int)(performance->game_speed_percent + 0.5),
	    (int)(performance->frames_per_second + 0.5),
	    (int)(Machine->refresh_rate + 0.5));
	}
	if ((i < 0) || (i >= (bufsize-1)))
	  return buffer;
	dest    += i;
	bufsize -= i;
	
        /* status message? */
        if (show_status)
        {
          show_status--;
          i = snprintf(dest, bufsize, "\n%s", status_msg);
	  if ((i < 0) || (i >= (bufsize-1)))
	    return buffer;
	  dest    += i;
	  bufsize -= i;
        }

	/* for hotkey chosen effect or scale add effect or scale */
	if (show_effect_or_scale)
	{
          show_effect_or_scale--;
          i = snprintf(dest, bufsize, "\n%s (%dx%d)",
            sysdep_display_effect_properties[normal_params.effect].name,
            normal_params.widthscale, normal_params.heightscale);
	  if ((i < 0) || (i >= (bufsize-1)))
	    return buffer;
	  dest    += i;
	  bufsize -= i;
        }
        
	/* for vector games, add the number of vector updates */
	if (Machine->drv->video_attributes & VIDEO_TYPE_VECTOR)
	  snprintf(dest, bufsize, "\n %d vector updates", performance->vector_updates_last_second);
	else if (performance->partial_updates_this_frame > 1)
	  snprintf(dest, bufsize, "\n %d partial updates", performance->partial_updates_this_frame);

	/* return a pointer to the static buffer */
	return buffer;
}

/*
 * We don't want to sleep when idle while the setup menu is
 * active, since this causes problems with registering
 * keypresses.
 */
int should_sleep_idle()
{
	return sleep_idle && !ui_is_setup_active();
}
