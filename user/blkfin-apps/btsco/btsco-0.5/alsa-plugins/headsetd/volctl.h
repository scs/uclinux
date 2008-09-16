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

#ifndef VOLCTL_H
#define VOLCTL_H

/* Forward declarations */
struct State;

/* Structures definitions */

typedef enum {SPEAKER, MICROPHONE} volume_t;

typedef struct ctl_packet {
	unsigned char type;
	volume_t voltype;
	unsigned char volvalue;
} ctl_packet_t;

/*
  Called when data from control socket is available
*/
void volctl_ReadCtlApplSocket(struct State *s, short revents, void (*volwritefx)(volume_t, int));

/*
  Called when an application wants to set volume and headset
  is ready to take it.
*/
void volctl_write_fromappl(volume_t type, int value);

/*
  Called when an application wants to set volume and headset
  is NOT ready to take it.
*/
void volctl_write_fromappl_unconnected(volume_t type, int value);

/*
  Called when headset sends its volumes.
*/
int volctl_write_fromhs(const char * atcmd);

/*
  Called when an application wants to read a volume
*/

int  volctl_read_fromappl(volume_t type);

void volctl_release();

#endif /* VOLCTL_H */
