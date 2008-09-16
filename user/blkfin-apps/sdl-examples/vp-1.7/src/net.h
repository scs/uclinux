
/*****************************************************************************
 * vp    -    SDL based image viewer for linux and fbsd. (X and console)     *
 * Copyright (C) 2001-2007 Erik Greenwald <erik@smluc.org>                   *
 *                                                                           *
 * This program is free software; you can redistribute it and/or modify      *
 * it under the terms of the GNU General Public License as published by      *
 * the Free Software Foundation; either version 2 of the License, or         *
 * (at your option) any later version.                                       *
 *                                                                           *
 * This program is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 * GNU General Public License for more details.                              *
 *                                                                           *
 * You should have received a copy of the GNU General Public License         *
 * along with this program; if not, write to the Free Software               *
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA *
 ****************************************************************************/

/*
 * $Id: net.h,v 1.11 2007/01/10 15:55:27 erik Exp $
 */

#ifndef __NET_H_
#define __NET_H_

#define HTTP 0x1
#define FTP  0x2

typedef struct {
    /*
     * file descriptors 
     */
    int file;
    int conn;
    /*
     * connection info 
     */
    int proto;			/* uh */
    char *server;		/* DNS name of server */
    int port;			/* numeric port value */
    char *filename;		/* file on server to get... */
    /*
     * mime info 
     */
    char *mimetype;
    char *ext;
} url_t;

int net_is_url (char *name);
char *net_download (char *name);
void net_purge (char *file);
url_t *net_url (char *name);

#endif
