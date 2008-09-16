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

#ifndef SOCKETS_H
#define SOCKETS_H

#define IDX_RFCOMM_SRV_SOCK   0
#define IDX_PCM_APPL_SRV_SOCK 1
#define IDX_CTL_APPL_SRV_SOCK 2
#define IDX_RFCOMM_SOCK       3
#define IDX_SCO_SOCK          4
#define IDX_PCM_APPL_SOCK     5
#define IDX_SDP_SOCK          6

#define DAEMON_NUM_SOCKS 7

extern	int hspd_sockets[DAEMON_NUM_SOCKS];

#endif
