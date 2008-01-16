/*
 *     XFree86 VidMode and DGA support by Jens Vaasjo <jvaasjo@iname.com>
 *     Modified for DGA 2.0 support
 *     by Shyouzou Sugitani <shy@debian.or.jp>
 *     Stea Greene <stea@cs.binghamton.edu>
 */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/xf86dga.h>
#include <X11/extensions/xf86vmode.h>
#include "sysdep/sysdep_display_priv.h"
#include "x11.h"

static int  (*p_xf86_dga_open_display)(int reopen);
static void (*p_xf86_dga_close_display)(void);
static const char * (*p_xf86_dga_update_display)(mame_bitmap *,
	  rectangle *vis_area, rectangle *dirty_area,
	  struct sysdep_palette_struct *palette, int flags);
static void (*p_xf86_dga_clear_display)(void);

struct rc_option xf86_dga_opts[] = {
  /* name, shortname, type, dest, deflt, min, max, func, help */
#ifdef X_XDGASetMode
  { "DGA Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
  { NULL, NULL, rc_link, xf86_dga2_opts, NULL, 0, 0, NULL, NULL },
#endif  
  { NULL, NULL, rc_link, mode_opts, NULL, 0, 0, NULL, NULL },
  { NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

int xf86_dga_init(void)
{
	int i, j;
	char *s;

	if(geteuid())
		fprintf(stderr,"DGA requires root rights\n");
	else if (!(s = getenv("DISPLAY")) || (s[0] != ':'))
                fprintf(stderr,"DGA only works on a local display\n");
        else if(!XF86DGAQueryExtension(display, &i, &i))
                fprintf(stderr,"XF86DGAQueryExtension failed\n");
        else if(!XF86DGAQueryVersion(display, &i, &j))
                fprintf(stderr,"XF86DGAQueryVersion failed\n");
#ifdef X_XDGASetMode
        else if (i >= 2)
        {
                p_xf86_dga_open_display   = xf86_dga2_open_display;
                p_xf86_dga_close_display  = xf86_dga2_close_display;
                p_xf86_dga_update_display = xf86_dga2_update_display;
                p_xf86_dga_clear_display  = xf86_dga2_clear_display;
                return xf86_dga2_init();
        }
#endif
        else
        {
                p_xf86_dga_open_display   = xf86_dga1_open_display;
                p_xf86_dga_close_display  = xf86_dga1_close_display;
                p_xf86_dga_update_display = xf86_dga1_update_display;
                p_xf86_dga_clear_display  = xf86_dga1_clear_display;
                return xf86_dga1_init();
        }

	fprintf(stderr,"Use of DGA-modes is disabled\n");
	return 1;
}

int xf86_dga_open_display(int reopen)
{
  return p_xf86_dga_open_display(reopen);
}

void xf86_dga_close_display(void)
{
  p_xf86_dga_close_display();
}

const char *xf86_dga_update_display(mame_bitmap *bitmap,
	  rectangle *vis_area, rectangle *dirty_area,
	  struct sysdep_palette_struct *palette, int flags)
{
  return p_xf86_dga_update_display(bitmap, vis_area, dirty_area,
    palette, flags);
}

void xf86_dga_clear_display(void)
{
  p_xf86_dga_clear_display();
}
