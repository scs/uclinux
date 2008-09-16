
/*****************************************************************************
 * vp    -    SDL based image viewer for linux and fbsd. (X and console)     *
 * Copyright (C) 2001-2007 Erik Greenwald <erik@smluc.org>                   *
 *                                                                           *
 * This program is free software; you can redistribute it and/or modify      *
 * it under the terms of the GNU General Public License as published by      *
 * the Free Software Foundation; either version 2 of the License, or         *
 * (at your option) any later version.                                       *
 *                                                                           *
 * This program is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 * GNU General Public License for more details.                              *
 *                                                                           *
 * You should have received a copy of the GNU General Public License         *
 * along with this program; if not, write to the Free Software               *
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA *
 ****************************************************************************/

/* 
 * $Id: image.c,v 1.49 2007/02/01 15:18:05 erik Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <SDL.h>
#include <SDL_syswm.h>
#include <SDL_image.h>

#include "vp.h"

extern SDL_Surface *screen;
extern SDL_mutex *mutex;

void
sync ()
{
#ifdef SDL_SYSWM_X11
    SDL_SysWMinfo info;

    SDL_VERSION (&info.version);
    if (SDL_GetWMInfo (&info) > 0)
    {
	if (info.subsystem == SDL_SYSWM_X11)
	    XSync (info.info.x11.display, False);
    }
#endif
    return;
}

static double
getscale (double sw, double sh, double iw, double ih)
{
    return (sh * iw < ih * sw) ? sh / ih : sw / iw;
}

	/*
	 * hideous. This should be made more readable, and probably faster.
	 * be nice if it did multi-sampling to get cleaner zooming?
	 */
SDL_Surface *
zoom_blit (SDL_Surface * d, SDL_Surface * s, float scale)
{
    static int x, y, bpp, doff, soff, width;

    bpp = s->format->BytesPerPixel;
    width = d->w;

    for (y = 0; y < d->h; y++)
	for (x = 0; x < width; x++)
	{
	    doff = d->pitch * y + x * bpp;
	    soff =
		(int)((int)(s->pitch) * (int)(y / scale)) +
		(bpp * (int)((x) / scale));
/* TODO this pointer casting causes warnings on 64b */
	    memcpy ((void *)((int)d->pixels + doff),
		(void *)((int)s->pixels + soff), bpp);
	}
    return d;
}

	/*
	 * ripped from the libsdl faq, 'gtv' code 
	 */
static void
center_window ()
{
    SDL_SysWMinfo info;

    SDL_VERSION (&info.version);
    if (SDL_GetWMInfo (&info) > 0)
    {
#ifdef SDL_SYSWM_X11
	int x, y, w, h;

	if (info.subsystem == SDL_SYSWM_X11)
	{
	    info.info.x11.lock_func ();
	    w = DisplayWidth (info.info.x11.display,
		DefaultScreen (info.info.x11.display));
	    h = DisplayHeight (info.info.x11.display,
		DefaultScreen (info.info.x11.display));
	    x = (w - screen->w) / 2;
	    y = (h - screen->h) / 2;
	    XMoveWindow (info.info.x11.display, info.info.x11.wmwindow, x, y);

/*
	    if (get_state_int (GRAB_FOCUS))
		XSetInputFocus (info.info.x11.display, info.info.x11.wmwindow,
		    RevertToNone, CurrentTime);
*/
	    info.info.x11.unlock_func ();
	}
#endif
    }
    return;
}

void
show_image ()
{
    struct image_table_s *it = get_image_table ();
    SDL_Rect r;
    SDL_Surface *s;

    if (get_state_int (LOUD))
    {
	fprintf (stdout, "%s\n", it->image[it->current].resource);
	fflush (stdout);
    }

    s = it->image[it->current].surface;
    if (s == NULL)
	return;
    if (get_state_int (FULLSCREEN))
    {
	SDL_FillRect (screen, NULL, 0);
	if (get_state_int (ZOOM))
	    s = it->image[it->current].scaled;
    } else
    {
	static char buffer[BUFSIZ];

	screen = SDL_SetVideoMode (s->w, s->h, vid_depth (), SDL_DOUBLEBUF);
	snprintf (buffer, BUFSIZ, "vp - %s", it->image[it->current].resource);
	SDL_WM_SetCaption (buffer, "vp");
	center_window ();
    }
    if (s && s->format)
    {
	r.x = (Sint16) (screen->w - s->w) / 2;
	r.y = (Sint16) (screen->h - s->h) / 2;
	r.w = (Uint16) s->w;
	r.h = (Uint16) s->h;
    } else
	printf ("Image \"%s\" failed\n", it->image[it->current].resource);
    SDL_BlitSurface (s, NULL, screen, &r);
    SDL_Flip (screen);
    return;
}

/* saw a crash in here on g5 -fast 
 * Exception:  EXC_BAD_ACCESS (0x0001)
 * Codes:      KERN_INVALID_ADDRESS (0x0001) at 0x02730003
 *
 * Thread 0 Crashed:
 * 0   <<00000000>>	0xffff8834 __memcpy + 148 (cpu_capabilities.h:189)
 * 1   vp				0x00003154 image_freshen_sub + 836
 * 2   vp				0x00003284 image_freshen + 212
 * 3   vp				0x00003310 image_prev + 80
 */
void
image_freshen_sub (struct image_s *i)
{
    if (i->surface == NULL)
    {
	i->surface = IMG_Load (i->file);
    }
    if (i->scaled == NULL && get_state_int (ZOOM))
    {
	double scale =
	    getscale (screen->w, screen->h, i->surface->w, i->surface->h);

	i->scaled = SDL_CreateRGBSurface (SDL_SWSURFACE,
	    (int)ceil ((double)i->surface->w * (double)scale) + 1,
	    (int)ceil ((double)i->surface->h * (double)scale) + 1,
	    i->surface->format->BytesPerPixel * 8,
	    i->surface->format->Rmask, i->surface->format->Gmask,
	    i->surface->format->Bmask, i->surface->format->Amask);
	if (i->scaled->format->BytesPerPixel == 1)
	    memcpy (i->scaled->format->palette, i->surface->format->palette,
		sizeof (SDL_Palette));
	zoom_blit (i->scaled, i->surface, scale);
    }
    return;
}

int
image_freshen ()
{
    struct image_table_s *it = get_image_table ();
    int c;

    SDL_LockMutex (mutex);

    sync ();
    c = it->current;

    if (c > 0)
    {
	struct image_s *i = &it->image[c - 1];

	if (i->surface)
	    SDL_FreeSurface (i->surface);
	if (i->scaled)
	    SDL_FreeSurface (i->scaled);
	i->surface = i->scaled = NULL;
    }
    if (c < (it->count - 1))
    {
	struct image_s *i = &it->image[c + 1];

	if (i->surface)
	    SDL_FreeSurface (i->surface);
	if (i->scaled)
	    SDL_FreeSurface (i->scaled);
	i->surface = i->scaled = NULL;
    }

    image_freshen_sub (&it->image[c]);
    show_image ();
    sync ();
    SDL_UnlockMutex (mutex);
    return 1;
}

int
image_next ()
{
    struct image_table_s *it = get_image_table ();

    SDL_LockMutex (mutex);

    if (it->current < (it->count - 1))
	it->current++;
    else
	return 0;
    SDL_UnlockMutex (mutex);
    image_freshen ();
    return 1;
}

int
image_prev ()
{
    struct image_table_s *it = get_image_table ();

    SDL_LockMutex (mutex);

    if (it->current > 0)
	it->current--;
    else
	return 0;
    SDL_UnlockMutex (mutex);
    image_freshen ();
    return 1;
}
