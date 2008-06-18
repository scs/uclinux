/*
 *
 *  Headset Profile support for Linux
 *
 *  Copyright (C) 2006  Fabien Chevalier
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef DAEMON_H
#define DAEMON_H

#include <sockets.h>
#include <states.h>
#include <sys/poll.h>

struct Daemon {
	/* private data */
	struct State *_cur_state;
};

/* Constructor */
extern int createDaemon(struct Daemon* d);

extern void daemon_enterLoop(struct Daemon *this);
extern void daemon_destroy        (struct Daemon *this);

#endif
