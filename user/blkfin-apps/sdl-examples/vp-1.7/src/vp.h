
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
 * $Id: vp.h,v 1.10 2007/01/10 15:55:27 erik Exp $
 */

#ifndef __VP_H_
#define __VP_H_

#define ZOOM		1
#define FULLSCREEN	2
#define LOUD		4
#define GRAB_FOCUS	8

struct image_s {
    char *resource;
    char *file;
    SDL_Surface *surface;
    SDL_Surface *scaled;
};

struct image_table_s {
    int count;
    int current;
    struct image_s *image;
};


void oops (char *);
int get_state_int (int);
int toggle_state (int);
int set_state_int (int);
int unset_state_int (int);
struct image_table_s *get_image_table ();
unsigned int vid_width ();
unsigned int vid_height ();
unsigned int vid_depth ();

#endif
