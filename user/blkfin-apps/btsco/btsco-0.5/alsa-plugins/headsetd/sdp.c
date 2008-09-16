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

#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/l2cap.h>

#include "sdp.h"

static inline int sdp_is_local(const bdaddr_t *device)
{
	return memcmp(device, BDADDR_LOCAL, sizeof(bdaddr_t)) == 0;
}

sdp_session_t *sdp_headset_register(uint8_t channel)
{
	sdp_list_t *svclass, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, l2cap, rfcomm, hag, ga;
	sdp_profile_desc_t profile[1];
	sdp_list_t *proto[2];
	int status;
	sdp_session_t *sdp_session;
	sdp_record_t *sdp_record;

	sdp_session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
	if (!sdp_session) {
		syslog(LOG_ERR, "Failed to connect to the local SDP server. %s(%d)", 
				strerror(errno), errno);
		return 0;
	}

	sdp_record = sdp_record_alloc();
	if (!sdp_record) {
		syslog(LOG_ERR, "Failed to allocate service record");
		sdp_close(sdp_session);
		return 0;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(sdp_record, root);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq    = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	proto[1] = sdp_list_append(proto[1], sdp_data_alloc(SDP_UINT8, &channel));
	apseq    = sdp_list_append(apseq, proto[1]);

	aproto   = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(sdp_record, aproto);

	sdp_uuid16_create(&hag, HEADSET_AGW_PROFILE_ID);    /* Headset Audio gateway */
	sdp_uuid16_create(&ga,  GENERIC_AUDIO_SVCLASS_ID);  /* Generic Audio */

	svclass = sdp_list_append(NULL, &hag);
	svclass = sdp_list_append(svclass, &ga);
	sdp_set_service_classes(sdp_record, svclass);

	sdp_uuid16_create(&profile[0].uuid, HEADSET_AGW_SVCLASS_ID); /* Audio Gateway */
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(sdp_record, pfseq);

	sdp_set_info_attr(sdp_record, "Audio Gateway", NULL, NULL);

	status = sdp_device_record_register(sdp_session, BDADDR_ANY, sdp_record, 0);
	sdp_record_free(sdp_record);
	if (status) {
		sdp_close(sdp_session);
		syslog(LOG_ERR, "SDP registration failed.");
		return 0;
	}
	return sdp_session;
}

sdp_session_t *sdp_connect_async(const bdaddr_t *src, const bdaddr_t *dst, uint32_t flags)
{
	int err;
	sdp_session_t *session = malloc(sizeof(sdp_session_t));
	if (!session)
		return session;
	memset(session, 0, sizeof(*session));
	session->flags = flags;
	if (sdp_is_local(dst)) {
		struct sockaddr_un sa;

		// create local unix connection
		session->sock = socket(PF_UNIX, SOCK_STREAM, 0);
		session->local = 1;
		if (session->sock >= 0) {
			sa.sun_family = AF_UNIX;
			strcpy(sa.sun_path, SDP_UNIX_PATH);
			if (connect(session->sock, (struct sockaddr *)&sa, sizeof(sa)) == 0)
				return session;
		}
	} else {
		struct sockaddr_l2 sa;

		// create L2CAP connection
		session->sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
		session->local = 0;
		if (session->sock >= 0) {
			sa.l2_family = AF_BLUETOOTH;
			sa.l2_psm = 0;
			if (bacmp(src, BDADDR_ANY) != 0) {
				sa.l2_bdaddr = *src;
				if (bind(session->sock, (struct sockaddr *) &sa, sizeof(sa)) < 0)
					goto fail;
			}
			if (flags & SDP_WAIT_ON_CLOSE) {
				struct linger l = { .l_onoff = 1, .l_linger = 1 };
				setsockopt(session->sock, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
			}
			sa.l2_psm = htobs(SDP_PSM);
			sa.l2_bdaddr = *dst;
			if(fcntl(session->sock, F_SETFL, O_NONBLOCK) < 0) {
				goto fail;
			}
			if ( (connect(session->sock, (struct sockaddr *) &sa, sizeof(sa)) == 0) || (errno == EAGAIN) || (errno == EINPROGRESS) )
				return session;
		}
	}
fail:
	err = errno;
	if (session->sock >= 0)
		close(session->sock);
	free(session);
	errno = err;
	return 0;
}

