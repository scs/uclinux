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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <errno.h>
#include <assert.h>

#include "volctl.h"
#include "sockets.h"

/* Local defines */
#define CTLS_COUNT 2

#define MINVOL 0
#define MAXVOL 15

  /* We should not have to define this, however it looks like it is defined nowere,
     and even hardcoded in sys/un.h */
#define UNIX_PATH_MAX 108

  /* Control (CTL) packet types */
#define PKT_TYPE_CTL_CMD_GET       0
#define PKT_TYPE_CTL_CMD_SET       1
#define PKT_TYPE_CTL_GET_RSP       2
#define PKT_TYPE_CTL_NTFY          3

/* Local typedefs */
typedef struct ctl_appl_list_node {
	struct sockaddr_un address;
	struct ctl_appl_list_node *next;
} ctl_appl_list_node_t;

/* Local variables */
static int vols[CTLS_COUNT] = {7, 7};
  /* Last recently used control applications */
static ctl_appl_list_node_t *ctl_appl_list = 0;

/* Local functions */
static void volctl_register_appl(const struct sockaddr_un * appl_address);
static void volctl_notify_change(const struct sockaddr_un * appl_address, volume_t voltype);

void volctl_write_fromappl(volume_t type, int value)
{
	char volstr[32];
	assert(hspd_sockets[IDX_RFCOMM_SOCK] != 0);
	if((value >= MINVOL) && (value <= MAXVOL)) {
		vols[type] = value;
		sprintf(volstr, "\r\n+VG%c=%d\r\n", (type == SPEAKER ? 'S' : 'M'), value);
#ifndef NDEBUG
		fprintf(stderr, "Sending to headset: %s", volstr);
#endif
		if(send(hspd_sockets[IDX_RFCOMM_SOCK], volstr, strlen(volstr), MSG_NOSIGNAL) < 0) {
			syslog(LOG_ERR, "Unable to send volume change to headset : %s", strerror(errno));
		}
	}
	/* else : do not print anything anywhere */
}

void volctl_write_fromappl_unconnected(volume_t type, int value)
{
	if((value >= MINVOL) && (value <= MAXVOL)) {
		vols[type] = value;
	}
	/* else : do not print anything anywhere */
}

int volctl_write_fromhs(const char * atcmd)
{
	volume_t type;
	/* AT+VGS */
	if(atcmd[5] == 'S') {
		type = SPEAKER;
	}
	/* AT+VGM */
	else if(atcmd[5] == 'M') {
		type = MICROPHONE;
	}
#ifndef NDEBUG
	else {
		abort();
	}
#endif

	const char *startptr = atcmd + strlen("AT+VGx=");
	char *endptr;
	int value = strtol(startptr, &endptr, 10);
	if((endptr[0] == '\0' || endptr[0] == '\r') && (value >= MINVOL) && (value <= MAXVOL)) { /* Ok */
		vols[type] = value;
		volctl_notify_change(0, type);
		return 0;
	}
	else {
		syslog(LOG_ERR, "Wrong command received from Headset: '%s'", atcmd);
		return -1;
	}
}

int  volctl_read_fromappl(volume_t type)
{
	if(type >= 0 && type <= CTLS_COUNT) { 
		return vols[type];
	}
	else {
		return 0;
	}
}

void volctl_ReadCtlApplSocket(struct State *s, short revents, void (*volwritefx)(volume_t, int))
{
	if((revents & (POLLHUP | POLLERR)) == 0) {
		ctl_packet_t pkt;
		struct sockaddr_un unixaddr;
		socklen_t addrlen = sizeof(unixaddr);
		if(recvfrom(hspd_sockets[IDX_CTL_APPL_SRV_SOCK], &pkt, sizeof(pkt), 0, 
			(struct sockaddr *)&unixaddr, &addrlen) == sizeof(pkt)) {
			switch(pkt.type) {
			case PKT_TYPE_CTL_CMD_SET:
				(*volwritefx)(pkt.voltype, pkt.volvalue);
				volctl_notify_change(&unixaddr, pkt.voltype);
				volctl_register_appl(&unixaddr);
				break;
			case PKT_TYPE_CTL_CMD_GET:
				pkt.type     = PKT_TYPE_CTL_GET_RSP;
				pkt.volvalue = volctl_read_fromappl(pkt.voltype);
				if(sendto(hspd_sockets[IDX_CTL_APPL_SRV_SOCK], &pkt, sizeof(pkt), 
					MSG_NOSIGNAL, (struct sockaddr *)&unixaddr, addrlen) > 0) {
					volctl_register_appl(&unixaddr);
				}
				else {
					syslog(LOG_ERR, "Unable to send volume to ctl appl : %s", strerror(errno));
				}
				break;
			default:
				syslog(LOG_ERR, "Unexpected ctl packet type %d received", pkt.type);
			}
		}
	}
}

static void volctl_register_appl(const struct sockaddr_un * appl_address)
{
 	ctl_appl_list_node_t * curitem;
	int already_in_list = 0;

	for(curitem = ctl_appl_list; curitem != 0; curitem = curitem->next) {
		if(strncmp(appl_address->sun_path + 1, curitem->address.sun_path + 1, UNIX_PATH_MAX - 1) == 0) {
			already_in_list = 1;
			break;
		}
	}

	if(!already_in_list) {
		ctl_appl_list_node_t * newitem = malloc(sizeof(ctl_appl_list_node_t));
		memcpy(&newitem->address, appl_address, sizeof(struct sockaddr_un));
		/* Insert us in list */
		newitem->next = ctl_appl_list;
		ctl_appl_list = newitem;
	}
}

static void volctl_notify_change(const struct sockaddr_un * appl_address, volume_t voltype)
{
 	ctl_appl_list_node_t * curitem = ctl_appl_list;
	ctl_packet_t pkt;
	
	while(curitem != 0) {
		int incremented = 0;
		if(!appl_address || 
			strncmp(appl_address->sun_path + 1, curitem->address.sun_path + 1, UNIX_PATH_MAX - 1) != 0) {
			/* Not us, trying to ring the bell !! */
			pkt.type = PKT_TYPE_CTL_NTFY;
			pkt.voltype = voltype;
			pkt.volvalue = 0;
			int r = sendto(hspd_sockets[IDX_CTL_APPL_SRV_SOCK], &pkt, sizeof(pkt), MSG_NOSIGNAL, (struct sockaddr *)&curitem->address, sizeof(struct sockaddr_un));
			if(r < 0) {
				if(errno == ECONNREFUSED) {
					/* Application closed, remove item from the list */
					ctl_appl_list_node_t *item, *previtem;
					for(item = ctl_appl_list, previtem = 0;
					item != 0; previtem = item, item = item->next) {
						if(item == curitem) {
							/* remove curitem */
							if(previtem) {
								previtem->next = item->next;
							}
							else {
								ctl_appl_list = item->next;
							}
							/* we need to increment before free */
							incremented = 1;
							curitem = curitem->next;
							free(item);
							break;
						}
					}
				}
				else {
					syslog(LOG_ERR, "Unable to sendto : %s", strerror(errno));
				}
			}
		}
		if(!incremented) {
			curitem = curitem->next;
		}
	}
}

void volctl_release()
{
 	ctl_appl_list_node_t * curitem = ctl_appl_list;
	
	while(curitem != 0) {
		free(curitem);
		curitem = curitem->next;
	}

	ctl_appl_list = 0;
}
