/*
 * Linux ABS event driven (/dev/input/event*) lightgun support.
 *
 * Copyright (C) 2003  Ben Collins <bcollins@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __LIGHTGUN_ABS_EVENT_H__
#define __LIGHTGUN_ABS_EVENT_H__

extern struct rc_option lightgun_abs_event_opts[];

int lightgun_event_abs_read(int joynum, int joyindex, int *delta);
void lightgun_event_abs_init(void);
void lightgun_event_abs_poll(void);

#endif /* __LIGHTGUN_ABS_EVENT_H__ */
