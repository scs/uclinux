/* MAME Photon 2 Code
 *
 * Writen By: Travis Coady
 * Origional Code By: David Rempel
 *
 * web: http://www.classicgaming.com/phmame/
 * e-mail: smallfri@bigfoot.com
 *
 * Copyright (C) 2000-2001, The PhMAME Developement Team.
*/

/* Include files */
#define __PH_C__

#include <math.h>
#include "photon2.h"
#include "input.h"
#include "sysdep/sysdep_display.h"

struct rc_option display_opts[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
   { "Photon Related",	NULL,			rc_seperator,	NULL,
     NULL,		0,			0,		NULL,
     NULL },
   { "render-mode",	NULL,			rc_int,		&ph_video_mode,
     "0",		0,			PH_MODE_COUNT-1, NULL,
     "Select Photon rendering video mode:\n0 Normal window  (hotkey left-alt + insert)\n1 Fullscreen Video Overlay (hotkey left-alt + home)" },
   { NULL,		NULL,			rc_link,	ph_window_opts,
     NULL,		0,			0,		NULL,
     NULL },
     /*
   { NULL,		NULL,			rc_link,	ph_ovr_opts,
     NULL,		0,			0,		NULL,
     NULL },
     */
   { NULL,		NULL,			rc_link,	ph_input_opts,
     NULL,		0,			0,		NULL,
     NULL },
   { NULL,		NULL,			rc_end,		NULL,
     NULL,		0,			0,		NULL,
     NULL }
};

struct ph_func_struct {
   int  (*init)(void);
   int  (*create_display)(int depth);
   void (*close_display)(void);
   void (*update_display)(mame_bitmap *bitmap);
};

struct ph_func_struct ph_func[PH_MODE_COUNT] = {
{ NULL,
  ph_window_create_display,
  ph_window_close_display,
  ph_window_update_display },
#if 1
/*
{ NULL,
  ph_ovr_create_display,
  ph_ovr_close_display,
  ph_ovr_update_display }
*/
#else
  {NULL,NULL,NULL,NULL}
#endif
};

int sysdep_init (void)
{
   int i;
  
   // attach to default photon server 
   if(!(ph_ctx= PhAttach (NULL,NULL)))
   {
      fprintf (stderr, "error: could not open display\n");
      return OSD_NOT_OK;
   }
  
   // Initialize the Widget Library
   PtInit(NULL);  
   
   for (i=0;i<PH_MODE_COUNT;i++)
   {
      if(ph_func[i].create_display)
         mode_available[i] = TRUE;
      else
         mode_available[i] = FALSE;
      
      if(ph_func[i].init && (*ph_func[i].init)() != OSD_OK)
         return OSD_NOT_OK;
   }
   
   return OSD_OK;
}

void sysdep_close(void)
{
   if(ph_ctx)
      PhDetach(ph_ctx);
}

/* This name doesn't really cover this function, since it also sets up mouse
   and keyboard. This is done over here, since on most display targets the
   mouse and keyboard can't be setup before the display has. */
int sysdep_create_display (int depth)
{
   /* first setup the keyboard that's the same for all X video modes */
//   local_key=phkey;
   memset((void *)&phkey[0], FALSE, 128*sizeof(unsigned char) );
  

   return (*ph_func[ph_video_mode].create_display)(depth);
}

void sysdep_display_close (void)
{
   (*ph_func[ph_video_mode].close_display)();
   /* free the bitmap after cleaning the dirty stuff as it uses the bitmap */
   //osd_free_bitmap (bitmap);
}

int ph_init_palette_info(void)
{
   memset(&display_palette_info, 0, sizeof(struct sysdep_palette_info));
#if 1   
	switch (depth)
	{
		case 16 :
			display_palette_info.red_mask = 0xF800;
			display_palette_info.green_mask = 0x07E0;
			display_palette_info.blue_mask = 0x001F;
			break;
		case 24 :
		case 32	:
			display_palette_info.red_mask = 0xFF0000;
			display_palette_info.green_mask = 0x00FF00;
			display_palette_info.blue_mask = 0x0000FF;
			break;
		return -1;	
	}
#endif
   return OSD_OK;
}

void sysdep_update_display (mame_bitmap *bitmap)
{
   extern unsigned short *shrinked_pens;
   int new_video_mode = ph_video_mode;
   
   int bitmap_depth = bitmap->depth;

   if (code_pressed (KEYCODE_LALT))
   { 
      if (code_pressed_memory (KEYCODE_INSERT))
         new_video_mode = PH_WINDOW;
         /*
      if (code_pressed_memory (KEYCODE_HOME))
         new_video_mode = PH_OVR;
         */
   }

   if (new_video_mode != ph_video_mode && mode_available[new_video_mode])
   {
      (*ph_func[ph_video_mode].close_display)();
      if ((*ph_func[new_video_mode].create_display)(bitmap_depth) != OSD_OK)
      {
         fprintf(stderr,
            "warning: could not create display for new photon-mode\n"
            "   Trying again with the old photon-mode\n");
         (*ph_func[new_video_mode].close_display)();
         if ((*ph_func[ph_video_mode].create_display)(bitmap_depth) != OSD_OK)
            goto barf;
         {
            sysdep_display_close();   /* This cleans up and must be called to
                                      restore the videomode with dga */
            osd_exit();
            sysdep_close();
            fprintf (stderr,
               "error: could not create new photon display while switching display modes\n");
            exit (1);              /* ugly, anyone know a better way ? */
         }
      }
      else
         ph_video_mode = new_video_mode;

      if(sysdep_palette_change_display(&current_palette))
         goto barf;
      
      memset((void *)&phkey[0], FALSE, 128*sizeof(unsigned char) );
      /* poll mouse twice to clear internal vars */
      sysdep_mouse_poll ();
      sysdep_mouse_poll ();
   }

   (*ph_func[ph_video_mode].update_display) (bitmap);
   return;
   
barf:   
   sysdep_display_close();   /* This cleans up and must be called to
                             restore the videomode with dga */
   osd_exit();
   sysdep_close();
   fprintf (stderr,
      "error: could not create new display while switching display modes\n");
   exit (1);              /* ugly, anyone know a better way ? */
}
