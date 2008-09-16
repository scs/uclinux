/*
 *
 *  Audio/Video Distribution Transport Protocol (AVDTP) library
 *
 *  Copyright (C) 2004  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __AVDTP_H
#define __AVDTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <bluetooth/bluetooth.h>

typedef void avdtp_t;

avdtp_t *avdtp_create(void);
int avdtp_bind(avdtp_t *, bdaddr_t *bdaddr);
int avdtp_discover(avdtp_t *avdtp, bdaddr_t *bdaddr);
int avdtp_connect(avdtp_t *avdtp, bdaddr_t *bdaddr, uint8_t seid);
int avdtp_close(avdtp_t *);
void avdtp_free(avdtp_t *);

#ifdef __cplusplus
}
#endif

#endif /* __AVDTP_H */
