/*
 * hw_livedrive.h - lirc routines for a Creative Labs LiveDrive.
 *
 *     Copyright (C) 2003 Stephen Beahm <stephenbeahm@adelphia.net>
 *
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version. 
 * 
 *     This program is distributed in the hope that it will be useful, 
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 *     GNU General Public License for more details. 
 * 
 *     You should have received a copy of the GNU General Public 
 *     License along with this program; if not, write to the Free 
 *     Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, 
 *     USA. 
 */

#ifndef HW_LIVEDRIVE_COMMON_H
#define HW_LIVEDRIVE_COMMON_H

struct sequencer_packet
{
	unsigned char type;
	unsigned char data;
	unsigned char device;
	unsigned char filler;
};

struct midi_packet
{
	unsigned char vendor_id[3];
	unsigned char dev;
	unsigned char filler[2];
	unsigned char keygroup;
	unsigned char remote[2];
	unsigned char key[2];
	unsigned char sysex_end;
};

/* midi_packet.dev */
#define REMOTE    0x60
#define NONREMOTE 0x61

int livedrive_decode(struct ir_remote *remote,
		     ir_code * prep, ir_code * codep, ir_code * postp,
		     int *repeat_flagp, lirc_t * remaining_gapp);
int livedrive_init(void);
int livedrive_deinit(void);

extern struct timeval start, end, last;
extern ir_code pre, code;

#define SYSEX     0xF0
#define SYSEX_END 0xF7

#endif /* HW_LIVEDRIVE_COMMON_H */
