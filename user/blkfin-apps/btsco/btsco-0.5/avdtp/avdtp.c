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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#include "avdtp.h"

#define AVDTP_PSM  25

struct avdtp_session {
	bdaddr_t src;
	bdaddr_t dst;

	int ssk;
};

static int l2cap_connect(bdaddr_t *src, bdaddr_t *dst, unsigned short psm, uint16_t *mtu)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opt;
	socklen_t len;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(psm);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	len = sizeof(opt);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opt, &len) < 0) {
		close(sk);
		return -1;
	}

	if (mtu)
		*mtu = opt.omtu;

	return sk;
}

avdtp_t *avdtp_create(void)
{
	struct avdtp_session *session;

	session = malloc(sizeof(*session));
	if (!session)
		return NULL;

	memset(session, 0, sizeof(*session));

	session->ssk = -1;

	return session;
}

int avdtp_bind(avdtp_t *avdtp, bdaddr_t *bdaddr)
{
	struct avdtp_session *session;

	if (!avdtp)
		return -EIO;

	session = avdtp;

	bacpy(&session->src, bdaddr);

	return 0;
}

int avdtp_discover(avdtp_t *avdtp, bdaddr_t *bdaddr)
{
	struct avdtp_session *session;

	if (!avdtp)
		return -EIO;

	session = avdtp;

	return 0;
}

int avdtp_connect(avdtp_t *avdtp, bdaddr_t *bdaddr, uint8_t seid)
{
	struct avdtp_session *session;
	int sk;

	if (!avdtp)
		return -EIO;

	session = avdtp;

	bacpy(&session->dst, bdaddr);

	sk = l2cap_connect(&session->src, &session->dst, AVDTP_PSM, NULL);
	if (sk < 0)
		return -EIO;

	session->ssk = sk;

	return 0;
}

int avdtp_close(avdtp_t *avdtp)
{
	struct avdtp_session *session;

	if (!avdtp)
		return -EIO;

	session = avdtp;

	if (session->ssk >= 0) {
		close(session->ssk);
		session->ssk = -1;
	}

	return 0;
}

void avdtp_free(avdtp_t *avdtp)
{
	struct avdtp_session *session;

	if (!avdtp)
		return;

	session = avdtp;

	avdtp_close(avdtp);

	memset(session, 0, sizeof(*session));
	free(session);
}
