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

#include <syslog.h>
#include <signal.h>
#include <alsa/asoundlib.h>
#include <alsa/control_external.h>

#include "a2dp_ipc.h"
#include "a2dpd_protocol.h"

/* Defines */

#define HS_SPEAKER    0
#define HS_MICROPHONE 1

#define MINVOL 0
#define MAXVOL 15

/* Debug */

#define NDEBUG
#ifdef NDEBUG
        #define DBG(fmt, arg...)
#else
        #define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
#endif

typedef enum {SPEAKER, MICROPHONE} volume_t;

typedef struct snd_ctl_a2dpd {
        snd_ctl_ext_t ext;
} snd_ctl_a2dpd_t;

static const char* vol_devices[] = { 
        "A2DPD0 Playback Volume",
        "A2DPD1 Capture Volume"
};

// Signal handler, there is a SIGPIPE sent when using tcp when the daemon is not running
// We catch it to not quit
void sighand(int signo)
{
        //printf("A2DPD CTL in signal handler %d\n", signo);
        return;
}

static void a2dpd_ctl_close(snd_ctl_ext_t *ext)
{
        snd_ctl_a2dpd_t *a2dpd = ext->private_data;
        close_socket(ext->poll_fd);
        free(a2dpd);
}

static int a2dpd_ctl_elem_count(snd_ctl_ext_t *ext)
{
        DBG("");
        return 2;
}

static int a2dpd_ctl_elem_list(snd_ctl_ext_t *ext, unsigned int offset, snd_ctl_elem_id_t *id)
{
        DBG("%d", offset);

        snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
        if (offset < 2) {
                snd_ctl_elem_id_set_name(id, vol_devices[offset]);
                DBG("=> %s", vol_devices[offset]);
                return 0;
        }
        else {
                return -EINVAL;
        }
}

static snd_ctl_ext_key_t a2dpd_ctl_find_elem(snd_ctl_ext_t *ext,
                                const snd_ctl_elem_id_t *id)
{
        const char *name = snd_ctl_elem_id_get_name(id);
        DBG("%s", name);

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

static int a2dpd_ctl_get_attribute(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
                        int *type, unsigned int *acc, unsigned int *count)
{
        DBG("");
        *type  = SND_CTL_ELEM_TYPE_INTEGER;
        *acc   = SND_CTL_EXT_ACCESS_READWRITE;
        *count = 1;
        return 0;
}

static int a2dpd_ctl_get_integer_info(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
                                long *imin, long *imax, long *istep)
{
        DBG("");
        *istep = 1;
        *imin  = MINVOL;
        *imax  = MAXVOL;
        return 0;
}

static int a2dpd_ctl_read_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key, long *value)
{
        AUDIOMIXERDATA AudioMixerData = INVALIDAUDIOMIXERDATA;
        DBG("");

        if(!value) return 0;

        *value = 8;

        int client_type=A2DPD_PLUGIN_CTL_READ;
        int sockfd=make_client_socket();

        if(send_socket(sockfd, &client_type, sizeof(client_type)) == sizeof(client_type))
        {
                if(recv_socket(sockfd, &AudioMixerData, sizeof(AudioMixerData)) == sizeof(AudioMixerData))
                {
                        if(key == HS_SPEAKER)
                        {
                                if(AudioMixerData.volume_speaker_right!=-1 && AudioMixerData.volume_speaker_left!=-1)
                                        *value = (AudioMixerData.volume_speaker_right+AudioMixerData.volume_speaker_left)/2;
                        }
                        else if(key == HS_MICROPHONE)
                        {
                                if(AudioMixerData.volume_micro_right!=-1 && AudioMixerData.volume_micro_left!=-1)
                                        *value = (AudioMixerData.volume_micro_right+AudioMixerData.volume_micro_left)/2;
                        }
                }
                else
                {
                        DBG("Unable to receive new volume value from server");
                }
        }
        else
        {
                DBG("Unable to request new volume value to server");
        }
        close_socket(sockfd);

        return 0;
}

static int a2dpd_ctl_write_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key, long *value)
{
        int iResult = 0;
        long curvalue;

        DBG("");

        a2dpd_ctl_read_integer(ext, key, &curvalue);

        if(value && *value != curvalue)
        {
                AUDIOMIXERDATA AudioMixerData = INVALIDAUDIOMIXERDATA;
                int client_type=A2DPD_PLUGIN_CTL_WRITE;
                int sockfd=make_client_socket();

                if(send_socket(sockfd, &client_type, sizeof(client_type)) == sizeof(client_type))
                {
                        if(key == HS_SPEAKER)
                        {
                                AudioMixerData.volume_speaker_right = *value;
                                AudioMixerData.volume_speaker_left = *value;
                        }
                        else if(key == HS_MICROPHONE)
                        {
                                AudioMixerData.volume_micro_right = *value;
                                AudioMixerData.volume_micro_left = *value;
                        }

                        if(send_socket(sockfd, &AudioMixerData, sizeof(AudioMixerData)) == sizeof(AudioMixerData))
                        {
                                iResult=1;
                        }
                        else
                        {
                                DBG("Unable to send new volume value to server");
                        }
                }
                else
                {
                        DBG("Unable to set new volume value to server");
                }
                close_socket(sockfd);
        }

        iResult=1;
        return iResult;
}

static int a2dpd_ctl_read_event(snd_ctl_ext_t *ext, snd_ctl_elem_id_t *id,
                        unsigned int *event_mask)
{
        AUDIOMIXERDATA AudioMixerData = INVALIDAUDIOMIXERDATA;
//	snd_ctl_a2dpd_t *a2dpd = ext->private_data;

        DBG("");
        syslog(LOG_INFO, "%s", __FUNCTION__);
        if(recv_socket(ext->poll_fd, &AudioMixerData, sizeof(AudioMixerData)) == sizeof(AudioMixerData))
        {
                snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);

                if(AudioMixerData.volume_speaker_right!=-1 || AudioMixerData.volume_speaker_left!=-1)
                        snd_ctl_elem_id_set_name(id, vol_devices[HS_SPEAKER]);
                else if(AudioMixerData.volume_micro_right!=-1 || AudioMixerData.volume_micro_left!=-1)
                        snd_ctl_elem_id_set_name(id, vol_devices[HS_MICROPHONE]);

                *event_mask = SND_CTL_EVENT_MASK_VALUE;
                return 1;
        }
        else
        {
                syslog(LOG_INFO, "error %s", __FUNCTION__);
                DBG("Unable to receive volume notification from server");
                return -errno;
        }
        return -EINVAL;
        /*
        if(recv(a2dpd->serverfd, &pkt, sizeof(pkt), MSG_DONTWAIT) == sizeof(pkt)) {
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
        }*/
}

static snd_ctl_ext_callback_t a2dpd_ext_callback = {
        .close            = a2dpd_ctl_close,
        .elem_count       = a2dpd_ctl_elem_count,
        .elem_list        = a2dpd_ctl_elem_list,
        .find_elem        = a2dpd_ctl_find_elem,
        .get_attribute    = a2dpd_ctl_get_attribute,
        .get_integer_info = a2dpd_ctl_get_integer_info,
        .read_integer     = a2dpd_ctl_read_integer,
        .write_integer    = a2dpd_ctl_write_integer,
        .read_event       = a2dpd_ctl_read_event,
};

SND_CTL_PLUGIN_DEFINE_FUNC(a2dpd)
{
        snd_config_iterator_t it, next;
        int err = 0;
        snd_ctl_a2dpd_t *a2dpd = 0;

        // set up thread signal handler
        signal(SIGPIPE, sighand);

        DBG("");
        snd_config_for_each(it, next, conf) {
                snd_config_t *n = snd_config_iterator_entry(it);
                const char *id;
                if (snd_config_get_id(n, &id) < 0)
                        continue;

                if (!strcmp(id, "comment") || !strcmp(id, "type"))
                //if (snd_pcm_conf_generic_id(id)) // Alsa-lib 1.0.11
                        continue;
                SNDERR("Unknown field %s", id);
                return -EINVAL;
        }

        a2dpd = malloc(sizeof(*a2dpd));
        if(a2dpd == NULL)
        {
                err=ENOMEM;
                goto error;
        }

        a2dpd->ext.version = SND_CTL_EXT_VERSION;
        a2dpd->ext.card_idx = 0; //FIXME
        strncpy(a2dpd->ext.id, "A2DPD CTL ID", sizeof(a2dpd->ext.id) - 1);
        strncpy(a2dpd->ext.driver, "A2DPD CTL Bluetooth Headset Driver", sizeof(a2dpd->ext.driver) - 1);
        strncpy(a2dpd->ext.name, "A2DPD CTL Headset Name", sizeof(a2dpd->ext.name) - 1);
        strncpy(a2dpd->ext.longname, "A2DPD CTL Headset Long Name", sizeof(a2dpd->ext.longname) - 1);
        strncpy(a2dpd->ext.mixername, "A2DPD CTL Headset Mixer Name", sizeof(a2dpd->ext.mixername) - 1);
        a2dpd->ext.callback = &a2dpd_ext_callback;
        a2dpd->ext.poll_fd = make_udp_socket();
        a2dpd->ext.private_data = a2dpd;

        err = snd_ctl_ext_create(&a2dpd->ext, name, mode);
        if (err < 0)
                goto error;

        *handlep = a2dpd->ext.handle;
        return 0;

error:
        if(a2dpd->ext.poll_fd!=-1) close_socket(a2dpd->ext.poll_fd);
        if(a2dpd != NULL) free(a2dpd);
        return err;
}

SND_CTL_PLUGIN_SYMBOL(a2dpd);
