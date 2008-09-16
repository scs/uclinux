/*
*
*  A2DPD - Bluetooth A2DP daemon for Linux
*
*  Copyright (C) 2006  Frédéric DALLEAU <frederic.dalleau@palmsource.com>
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
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#ifndef __A2DP_IPC_H__
#define __A2DP_IPC_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// Ipc shared
int make_udp_socket();
int make_client_socket();
int make_server_socket();
void setup_socket(int sockfd);
void close_socket(int sockfd);
int accept_socket(int sockfd);
int send_socket(int sockfd, void* buffer, int size);
int recv_socket(int sockfd, void* buffer, int size);
void async_run_process(char* cmd);

// Config files shared
void get_config_filename(char* filename, int buffersize);
void read_config_string(char* filename, char* section, char* key, char* returnbuffer, int buffersize, char* defvalue);
int read_config_int(char* filename, char* section, char* key, int defvalue);

#endif
