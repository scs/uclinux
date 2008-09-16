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

#include <config.h>
#include <stdio.h>

#include "dbus.h"

void signalHeadsetConnected(const bdaddr_t * hs_addr)
{
/* TODO : send DBUS signal */
#ifndef NDEBUG
	fprintf(stderr, "Headset connected\n");
#endif
}

void signalHeadsetDisconnected(const bdaddr_t * hs_addr)
{
/* TODO : send DBUS signal */
#ifndef NDEBUG
	fprintf(stderr, "Headset disconnected\n");
#endif
}

void signalHeadsetButtonPushed(const bdaddr_t * hs_addr)
{
/* TODO : send DBUS signal */
#ifndef NDEBUG
	fprintf(stderr, "Headset button pushed\n");
#endif
}
