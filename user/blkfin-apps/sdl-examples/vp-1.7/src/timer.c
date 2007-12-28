
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
 * $Id: timer.c,v 1.19 2007/01/10 15:55:27 erik Exp $
 */

#include <SDL.h>

#include "image.h"
#include "input.h"
#include "vp.h"
#include "timer.h"

static int wait_time = 2500;

SDL_TimerID timer_id;

int
timer_stub ()
{
    SDL_Event ev;

    if (image_next (1) == 0)
	throw_exit ();

    /*
     * thanks to Ted Mielczarek <tam4@lehigh.edu> for this, fixes the X
     * Async request errors 
     */

    ev.type = SDL_USEREVENT;
    ev.user.code = SHOW_IMAGE;

/*
    SDL_PushEvent (&ev);
*/
    return wait_time;
}

void
timer_toggle ()
{
    if (timer_id == 0)
	timer_start (wait_time);
    else
	timer_stop ();
    return;
}

void
timer_stop ()
{
    if (timer_id != 0)
	if (SDL_RemoveTimer (timer_id) == SDL_FALSE)
	    oops ("SDL_RemoveTimer() failed\n");
    timer_id = 0;
    return;
}

void
timer_start (int MILLIS)
{
    wait_time = MILLIS;
    if (timer_id == 0)
	timer_id =
	    SDL_AddTimer (wait_time, (SDL_NewTimerCallback) timer_stub, NULL);
    return;
}
