
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
 * $Id: input.c,v 1.30 2007/01/10 15:55:27 erik Exp $
 */

#include <ctype.h>
#include <SDL.h>
#include "image.h"
#include "input.h"
#include "vp.h"
#include "timer.h"

	/*
	 * these are ugly and shouldn't be here. Must redesign. 
	 */
extern SDL_Surface *screen, *img;
extern float scale;

	/*
	 * instead of actually exiting, we just fake the escape key 
	 */
void
throw_exit ()
{
    SDL_Event thrower;

    printf ("Throwing ext\n");
    thrower.type = SDL_KEYDOWN;
    thrower.key.keysym.sym = 27;
    timer_stop ();
    SDL_PushEvent (&thrower);
}

int
handle_input ()
{
    SDL_Event e;

    SDL_WaitEvent (&e);
    switch (e.type)
    {
	/*
	 * thanks to Ted Mielczarek <tam4@lehigh.edu> for this, fixes the X
	 * Async request errors 
	 */
    case SDL_USEREVENT:
	if (e.user.code == SHOW_IMAGE)
	    image_freshen ();
	break;
    case SDL_KEYDOWN:
	switch (tolower (e.key.keysym.sym))
	{
	case 'x':
	case 'q':
	case SDLK_ESCAPE:
	    return 0;
	    break;
	case SDLK_SPACE:
	    timer_toggle ();
	    break;
	case SDLK_RETURN:
	    image_freshen ();
	    timer_stop ();
	    break;
	case SDLK_RIGHT:
	    timer_stop ();
	    image_next (0);
	    break;
	case SDLK_LEFT:
	    timer_stop ();
	    image_prev (0);
	    break;
	case 'z':
	    timer_stop ();
	    toggle_state (ZOOM);
	    image_freshen ();
	    break;
	case 'f':
	    timer_stop ();
	    toggle_state (FULLSCREEN);
	    if (get_state_int (FULLSCREEN))
		screen =
		    SDL_SetVideoMode (vid_width (), vid_height (),
		    vid_depth (), SDL_FULLSCREEN | SDL_DOUBLEBUF);
	    image_freshen ();
	    break;
#if 0
	case '+':
	case '=':
	    scale += .1;
	    image_freshen ();
	    break;
	case '-':
	    scale -= .1;
	    image_freshen ();
	    break;
#endif
	default:
	    /*
	     * do nothing 
	     */
	    break;
	}
	break;
    case SDL_QUIT:
	return 0;
	break;
    }
    return 1;
}
