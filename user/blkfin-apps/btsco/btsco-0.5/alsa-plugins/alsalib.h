/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __ALSA_LIB_H__
#define __ALSA_LIB_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#define A2DPMAXIMUMTRANSFERUNITSIZE 610

typedef struct snd_pcm_alsa* LPALSA;

// Global library initialisation
extern void alsa_init( void);
extern void alsa_exit( void);

// Connect to alsa
extern LPALSA alsa_new( char* device, int framerate);
extern void alsa_destroy( LPALSA a2dp);

// transfers data
extern int alsa_transfer_raw( LPALSA a2dp, const char* pcm_buffer, int pcm_buffer_size);

#endif
