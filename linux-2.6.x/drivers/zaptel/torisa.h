/*
 * BSD Telephony Of Mexico "Tormenta" card LINUX driver, version 1.8 4/8/01
 * 
 * Working with the "Tormenta ISA" Card 
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 * Modified from original tor.c by Mark Spencer <markster@linux-support.net>
 *                     original by Jim Dixon <jim@lambdatel.com>
 */

#ifndef _LINUX_TORISA_H
#define _LINUX_TORISA_H

struct torisa_debug {
	unsigned int txerrors;
	unsigned int irqcount;
	unsigned int taskletsched;
	unsigned int taskletrun;
	unsigned int taskletexec;
	int span1flags;
	int span2flags;
};

/* Special torisa ioctl's */
#define TORISA_GETDEBUG		_IOW (ZT_CODE, 60, struct torisa_debug)

#endif
