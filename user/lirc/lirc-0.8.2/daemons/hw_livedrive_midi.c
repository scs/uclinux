/*
 * hw_livedrive_seq.c - lirc routines for a Creative Labs LiveDrive.
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

#include "hardware.h"
#include "ir_remote.h"
#include "hw_livedrive_common.h"

char *livedrive_rec_midi(struct ir_remote *remotes)
{
	int i;
	struct midi_packet midi;
	unsigned char *bytep = (unsigned char *) &midi;
	unsigned char buf;
	ir_code bit[4];

	last = end;

	gettimeofday(&start, NULL);
	/* poll for system exclusive status byte so we don't try to
	   record other midi events */
	do {
		read(hw.fd, &buf, sizeof(buf));
	}
	while (buf != SYSEX);

	for (i = 0; i < sizeof(midi); i++) {
		read(hw.fd, &buf, sizeof(buf));
		if (midi.dev == NONREMOTE && i == 4)   /* skip 2 missing filler bytes for audigy2 non-infrared messages */
			i += 2;
		*(bytep+i) = buf;
	}
	gettimeofday(&end, NULL);

	/* test for correct system exclusive end byte so we don't try
	   to record other midi events */
	if (midi.sysex_end != SYSEX_END)
		return (NULL);

	bit[0] = (midi.keygroup >> 3) & 0x1;
	bit[1] = (midi.keygroup >> 2) & 0x1;
	bit[2] = (midi.keygroup >> 1) & 0x1;
	bit[3] = (midi.keygroup >> 0) & 0x1;

	pre = reverse(midi.remote[0] |
		      (midi.remote[1] << 8), 16) | (bit[0] << 8) | bit[1];
	code = reverse(midi.key[0] |
		       (midi.key[1] << 8), 16) | (bit[2] << 8) | bit[3];

	return (decode_all(remotes));
}

struct hardware hw_livedrive_midi = {
	"/dev/midi",		/* simple device */
	-1,			/* fd */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,	/* rec_mode */
	32,			/* code_length */
	livedrive_init,		/* init_func */
	NULL,			/* config_func */
	livedrive_deinit,	/* deinit_func */
	NULL,			/* send_func */
	livedrive_rec_midi,	/* rec_func */
	livedrive_decode,	/* decode_func */
	NULL,                   /* ioctl_func */
	NULL,
	"livedrive_midi"
};
