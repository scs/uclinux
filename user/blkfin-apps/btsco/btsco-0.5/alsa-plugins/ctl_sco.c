/*
 * Bluetooth Headset ALSA Plugin
 *
 * Copyright (c) 2006 by Fabien Chevalier
 * 
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <alsa/asoundlib.h>
#include <alsa/control_external.h>

#include <config.h>

/* Defines */

#define CTL_SERVER_SOCKET "\0bluez-headset-ctl"

#define HS_SPEAKER    0
#define HS_MICROPHONE 1

#define MINVOL 0
#define MAXVOL 15

  /* Control (CTL) packet types */
#define PKT_TYPE_CTL_CMD_GET       0
#define PKT_TYPE_CTL_CMD_SET       1
#define PKT_TYPE_CTL_GET_RSP       2
#define PKT_TYPE_CTL_NTFY          3

/* Debug */

#define NDEBUG

#ifdef NDEBUG
	#define DBG(fmt, arg...)
#else
	#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
#endif

typedef enum {SPEAKER, MICROPHONE} volume_t;

typedef struct snd_ctl_sco {
	snd_ctl_ext_t ext;
	int serverfd;
} snd_ctl_sco_t;

typedef struct ctl_packet {
	unsigned char type;
	volume_t      voltype;
	unsigned char volvalue;
} ctl_packet_t;

static const char* vol_devices[] = { 
	"PCM Playback Volume",
	"Capture Volume"
};

static void sco_ctl_close(snd_ctl_ext_t *ext)
{
	snd_ctl_sco_t *bt_headset = ext->private_data;
	DBG("");
	close(bt_headset->serverfd);
	free(bt_headset);
}

static int sco_ctl_elem_count(snd_ctl_ext_t *ext)
{
	DBG("");
	return 2;
}

static int sco_ctl_elem_list(snd_ctl_ext_t *ext, unsigned int offset, snd_ctl_elem_id_t *id)
{
	DBG("");

	snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
	if (offset < 2) {
		snd_ctl_elem_id_set_name(id, vol_devices[offset]);
		return 0;
	}
	else {
		return -EINVAL;
	}
}

static snd_ctl_ext_key_t sco_ctl_find_elem(snd_ctl_ext_t *ext,
				       const snd_ctl_elem_id_t *id)
{
	const char *name = snd_ctl_elem_id_get_name(id);
	DBG("");

	if(strcmp(name, vol_devices[0]) == 0) {
		return HS_SPEAKER;
	}
	else if(strcmp(name, vol_devices[1]) == 0) {
		return HS_MICROPHONE;
	}
	else {
		return SND_CTL_EXT_KEY_NOT_FOUND;
	}
}

static int sco_ctl_get_attribute(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
			     int *type, unsigned int *acc, unsigned int *count)
{
	DBG("");
	*type  = SND_CTL_ELEM_TYPE_INTEGER;
	*acc   = SND_CTL_EXT_ACCESS_READWRITE;
	*count = 1;
	return 0;
}

static int sco_ctl_get_integer_info(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
				long *imin, long *imax, long *istep)
{
	DBG("");
	*istep = 1;
	*imin  = MINVOL;
	*imax  = MAXVOL;
	return 0;
}

static int sco_ctl_read_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key, long *value)
{
	snd_ctl_sco_t *bt_headset = ext->private_data;
	ctl_packet_t pkt = {.type = PKT_TYPE_CTL_CMD_GET};
	DBG("");

	*value = 0;

	if(key == HS_SPEAKER) {
		pkt.voltype = SPEAKER;
	}
	else if(key == HS_MICROPHONE) {
		pkt.voltype = MICROPHONE;
	}
	else {
		return -EINVAL;
	}

	if(send(bt_headset->serverfd, &pkt, sizeof(pkt), MSG_NOSIGNAL) == sizeof(pkt)) {
		if(recv(bt_headset->serverfd, &pkt, sizeof(pkt), 0) == sizeof(pkt)) {
			if(pkt.type == PKT_TYPE_CTL_GET_RSP) {
				*value = pkt.volvalue;
			}
			else {
				SNDERR("Unexpected packet type %d received", pkt.type);
			}
		}
		else {
			SYSERR("Unable to receive new volume value from server");
		}
	}
	else {
		SYSERR("Unable to request new volume value to server");
	}

	return 0;	
}

static int sco_ctl_write_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key, long *value)
{
	snd_ctl_sco_t *bt_headset = ext->private_data;
	long curvalue;

	sco_ctl_read_integer(ext, key, &curvalue);

	if(*value == curvalue) {
		return 0;
	}
	else {
		ctl_packet_t pkt = {.type = PKT_TYPE_CTL_CMD_SET, .volvalue = (unsigned char)*value};
		if(key == HS_SPEAKER) {
			pkt.voltype = SPEAKER;
		}
		else if(key == HS_MICROPHONE) {
			pkt.voltype = MICROPHONE;
		}
		else {
			return -EINVAL;
		}
		if(send(bt_headset->serverfd, &pkt, sizeof(pkt), MSG_NOSIGNAL) != sizeof(pkt)) {
			SYSERR("Unable to send new volume value to server");			
		}
		return 1;
	}

}

static int sco_ctl_read_event(snd_ctl_ext_t *ext, snd_ctl_elem_id_t *id,
			  unsigned int *event_mask)
{
	snd_ctl_sco_t *bt_headset = ext->private_data;
	ctl_packet_t pkt;

	DBG("");
	if(recv(bt_headset->serverfd, &pkt, sizeof(pkt), MSG_DONTWAIT) == sizeof(pkt)) {
		if(pkt.type == PKT_TYPE_CTL_NTFY) {
			snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
			snd_ctl_elem_id_set_name(id, pkt.voltype == SPEAKER ? vol_devices[HS_SPEAKER] : vol_devices[HS_MICROPHONE]);
			*event_mask = SND_CTL_EVENT_MASK_VALUE;
			return 1;
		}
		else {
			SNDERR("Unexpected packet type %d received!", pkt.type);
			return -EAGAIN;
		}
	}
	else {
		return -errno;
	}
}

static snd_ctl_ext_callback_t sco_ext_callback = {
	.close            = sco_ctl_close,
	.elem_count       = sco_ctl_elem_count,
	.elem_list        = sco_ctl_elem_list,
	.find_elem        = sco_ctl_find_elem,
	.get_attribute    = sco_ctl_get_attribute,
	.get_integer_info = sco_ctl_get_integer_info,
	.read_integer     = sco_ctl_read_integer,
	.write_integer    = sco_ctl_write_integer,
	.read_event       = sco_ctl_read_event,
};


SND_CTL_PLUGIN_DEFINE_FUNC(sco)
{
	snd_config_iterator_t it, next;
	int err = 0;
	snd_ctl_sco_t *bt_headset = 0;
	int serverfd;
	struct sockaddr_un  server_location = {
		AF_UNIX, CTL_SERVER_SOCKET
	};
	struct sockaddr_un local_name;
	
	DBG("");

	snd_config_for_each(it, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(it);
		const char *id;
		if (snd_config_get_id(n, &id) < 0)
			continue;
		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0)
			continue;
		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	serverfd = socket(PF_LOCAL, SOCK_DGRAM, 0);

	err = connect(serverfd,
		(struct sockaddr *)&server_location, sizeof(server_location));
	if(err != 0) {
		err = errno;
		SNDERR("Socket connection returned %s", strerror(err));
		close(serverfd);
		serverfd = -1;
		return -err;
	}

	local_name.sun_family = PF_LOCAL;
	/* This is just a hack to generate a unique name */
	local_name.sun_path[0] = 0;
	sprintf(local_name.sun_path + 1, "ctl-bluetooth-headset-%p-%d", &local_name, getpid());
	err = bind(serverfd,
		(struct sockaddr *)&local_name, sizeof(local_name));
	if(err != 0) {
		err = errno;
		SNDERR("Socket bind returned %s", strerror(err));
		close(serverfd);
		serverfd = -1;
		return -err;
	}

	bt_headset = calloc(1, sizeof(*bt_headset));
	bt_headset->serverfd = serverfd;

	bt_headset->ext.version = SND_CTL_EXT_VERSION;
	bt_headset->ext.card_idx = 1; /* FIXME */
	strncpy(bt_headset->ext.id, "Headset", sizeof(bt_headset->ext.id) - 1);
	strncpy(bt_headset->ext.driver, "Bluetooth Headset", sizeof(bt_headset->ext.driver) - 1);
	strncpy(bt_headset->ext.name, "Headset", sizeof(bt_headset->ext.name) - 1);
	strncpy(bt_headset->ext.longname, "Headset", sizeof(bt_headset->ext.longname) - 1);
	strncpy(bt_headset->ext.mixername, "Headset", sizeof(bt_headset->ext.mixername) - 1);
	bt_headset->ext.callback = &sco_ext_callback;
	bt_headset->ext.poll_fd = serverfd;
	bt_headset->ext.private_data = bt_headset;

	err = snd_ctl_ext_create(&bt_headset->ext, name, mode);
	if (err < 0)
		goto error;

	*handlep = bt_headset->ext.handle;
	return 0;

 error:
	if (bt_headset->serverfd >= 0)
		close(bt_headset->serverfd);
	free(bt_headset);
	return err;
}

SND_CTL_PLUGIN_SYMBOL(sco);
