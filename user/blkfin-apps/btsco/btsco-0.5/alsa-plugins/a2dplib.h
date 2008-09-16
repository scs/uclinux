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

#ifndef __A2DP_LIB_H__
#define __A2DP_LIB_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../a2dp.h"
#include <stdio.h>

#define A2DPMAXIMUMTRANSFERUNITSIZE 610

// To send one L2CAP packets of 678 bytes, 4 ACL packets are sent, 3 are 192 bytes long, 
// 1 contains 49 bytes  => loss 192-49/4
// To send one L2CAP packets of 610 bytes, 3 ACL packets are sent, 2 are 192 bytes long, 
// 1 contains 165 bytes => loss 192-165/3

typedef struct snd_pcm_a2dp* LPA2DP;

// Global library initialisation
extern void a2dp_init( void);
extern void a2dp_exit( void);

// Connect to an a2dp provider
typedef struct
{
	char bdaddr[32];
	int framerate;
	int channels;
	int sbcbitpool;
} A2DPSETTINGS;

extern LPA2DP a2dp_new( A2DPSETTINGS* settings);
extern void a2dp_destroy( LPA2DP a2dp);

// compress and transfers data
extern int a2dp_transfer_raw( LPA2DP a2dp, const char* pcm_buffer, int pcm_buffer_size);

// a2dp server functions
int a2dp_make_listen_socket( unsigned short psm);
int a2dp_wait_connection( int sockfd, char* szRemote, int iRemoteSize, uint16_t *mtu);

// Returns 0 on receiving bad frame
// Returns negative on error
// Size of received frame on success
int a2dp_handle_avdtp_message( LPA2DP a2dp, int sockfd, struct avdtp_header* sent_packet, struct avdtp_header* answer, int answer_size);

#endif
