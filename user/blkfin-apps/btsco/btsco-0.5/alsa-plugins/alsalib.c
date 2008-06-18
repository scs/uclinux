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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include <netinet/in.h>

#include <pthread.h>
#include <alsa/asoundlib.h>
#include "alsalib.h"
#include "a2dpd_protocol.h"

#define NBSDPRETRIESMAX 0
#define NONSPECAUDIO 1
#define BUFS 2048

#define DBG(fmt, arg...) { if(errno!=0) printf("DEBUG: %s: (errno=%d:%s)" fmt "\n" , __FUNCTION__ , errno, strerror(errno), ## arg); else printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg); errno=0; }

//#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
//#define DBG(D...)

static struct sigaction actions;

typedef struct snd_pcm_alsa {
	snd_pcm_t *playback_handle;
} snd_pcm_alsa_t;

/*
*   Underrun and suspend recovery
*/

static int xrun_recovery(snd_pcm_t * handle, int err)
{
	if (err == -EPIPE) {	/* under-run */
		err = snd_pcm_prepare(handle);
		if (err < 0)
			printf("Can't recovery from underrun, prepare failed: %s\n", snd_strerror(err));
		return err;
	} else if (err == -ESTRPIPE) {
		while ((err = snd_pcm_resume(handle)) == -EAGAIN)
			sleep(1);	/* wait until the suspend flag is released */
		if (err < 0) {
			err = snd_pcm_prepare(handle);
			if (err < 0)
				printf("Can't recovery from suspend, prepare failed: %s\n", snd_strerror(err));
		}
		return err;
	}
	return err;
}

int alsa_transfer_raw(LPALSA alsa, const char *pcm_buffer, int pcm_buffer_size)
{
	int result = 0;

	result = snd_pcm_writei(alsa->playback_handle, pcm_buffer, pcm_buffer_size / A2DPD_FRAME_BYTES);
	switch (result) {
	case -EBADFD:
		DBG("EBADFD(%d)", result);
		break;
	case -EPIPE:
		// To manage underrun, we will try to ignore
		if(xrun_recovery(alsa->playback_handle, result) == 0)
			result = 0;
		DBG("EPIPE(%d)", result);
		break;
	case -ESTRPIPE:
		if(xrun_recovery(alsa->playback_handle, result) == 0)
			result=0;
		DBG("ESTRPIPE(%d)", result);
		break;
	}

	return result;
}

snd_pcm_alsa_t *alsa_alloc(void)
{
	snd_pcm_alsa_t *alsa;
	alsa = malloc(sizeof(*alsa));
	if (!alsa)
		return NULL;

	memset(alsa, 0, sizeof(*alsa));
	return alsa;
}

void alsa_free(snd_pcm_alsa_t * alsa)
{
	free(alsa);
}

static void sighand(int signo)
{
	return;
}

void alsa_init(void)
{
	// set up thread signal handler
	memset(&actions, 0, sizeof(actions));
	sigemptyset(&actions.sa_mask);
	actions.sa_flags = 0;
	actions.sa_handler = sighand;
	sigaction(SIGALRM, &actions, NULL);
}

void alsa_exit(void)
{
}

LPALSA alsa_new(char *device, int framerate)
{
	DBG("");
	snd_pcm_alsa_t *alsa = NULL;
	snd_pcm_hw_params_t *hw_params = NULL;
	int bcontinue = 1;
	char *devname = (device && device[0]) ? device : "plughw:0,0";

	alsa = alsa_alloc();
	if (!alsa) {
		DBG("Can't allocate");
		return NULL;
	}
	// Setup alsa
	bcontinue = bcontinue && (snd_pcm_open(&alsa->playback_handle, devname, SND_PCM_STREAM_PLAYBACK, 0) >= 0);
	DBG("snd_pcm_open()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params_malloc(&hw_params) >= 0);
	DBG("snd_pcm_hw_params_malloc()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params_any(alsa->playback_handle, hw_params) >= 0);
	DBG("snd_pcm_hw_params_any()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params_set_access(alsa->playback_handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED) >= 0);
	DBG("snd_pcm_hw_params_set_access()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params_set_format(alsa->playback_handle, hw_params, SND_PCM_FORMAT_S16_LE) >= 0);
	DBG("snd_pcm_hw_params_set_format()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params_set_rate(alsa->playback_handle, hw_params, framerate, 0) >= 0);
	DBG("snd_pcm_hw_params_set_rate()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params_set_channels(alsa->playback_handle, hw_params, 2) >= 0);
	DBG("snd_pcm_hw_params_set_channels()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_hw_params(alsa->playback_handle, hw_params) >= 0);
	DBG("snd_pcm_hw_params()==%d", bcontinue);
	bcontinue = bcontinue && (snd_pcm_prepare(alsa->playback_handle) >= 0);
	DBG("snd_pcm_prepare()==%d", bcontinue);

	// Free if allocated
	if (hw_params)
		snd_pcm_hw_params_free(hw_params);

	if (alsa->playback_handle != NULL) {
	}

	if (!bcontinue) {
		alsa_destroy(alsa);
		alsa = NULL;
	}

	return alsa;
}

void alsa_destroy(LPALSA alsa)
{
	DBG("");
	if (alsa->playback_handle != NULL) {
		snd_pcm_close(alsa->playback_handle);
	}
	alsa_free(alsa);
	DBG("OK");
}
