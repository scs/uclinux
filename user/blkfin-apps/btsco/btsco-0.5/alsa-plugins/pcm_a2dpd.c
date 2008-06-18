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
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>
#include <alsa/timer.h>

#include "a2dpd_protocol.h"
#include "a2dp_timer.h"
#include "a2dp_ipc.h"

#include "../a2dp.h"

#define NONSPECAUDIO 1
#define BUFS 1024

#define min(X, Y)  ((X) < (Y) ? (X) : (Y))
#define DBG(fmt, arg...)  printf("DEBUG: %s: (errno=%d:%s)" fmt "\n" , __FUNCTION__ , errno, strerror(errno), ## arg)
//#define DBG(D...)

// Signal handler, there is a strange SIGPIPE when the daemon is not running
// We catch it to not quit
void sighand(int signo)
{
	printf("A2DPD CTL in signal handler %d\n", signo);
	return;
}

typedef struct snd_pcm_a2dp {
	snd_pcm_ioplug_t io;
	int sk;
	int rate;
	int channels;
	snd_pcm_sframes_t num;
	unsigned int frame_bytes;
	TIMERINFO TimerInfos;
} snd_pcm_a2dp_t;

static int a2dp_disconnect(snd_pcm_a2dp_t * a2dp)
{
	//syslog(LOG_INFO, "Disconnected a2dp %p, sk %d", a2dp, a2dp->sk);
	close_socket(a2dp->sk);
	a2dp->sk = -1;
	return 0;
}

static int a2dp_connect(snd_pcm_a2dp_t * a2dp)
{
	if (a2dp->sk <= 0) {
		int sockfd = make_client_socket();
		a2dp->sk = -1;
		if (sockfd > 0) {
			int32_t client_type = A2DPD_PLUGIN_PCM_WRITE;
			if (send_socket(sockfd, &client_type, sizeof(client_type)) == sizeof(client_type)) {
				// Fill stream informations
				AUDIOSTREAMINFOS StreamInfos = INVALIDAUDIOSTREAMINFOS;
				StreamInfos.rate = a2dp->rate;
				StreamInfos.channels = a2dp->channels;
				StreamInfos.bitspersample = a2dp->frame_bytes/a2dp->channels;
				switch(a2dp->io.format) {
				case SND_PCM_FORMAT_S8:     StreamInfos.format = A2DPD_PCM_FORMAT_S8; break;
				case SND_PCM_FORMAT_U8:     StreamInfos.format = A2DPD_PCM_FORMAT_U8; break;
				case SND_PCM_FORMAT_S16_LE: StreamInfos.format = A2DPD_PCM_FORMAT_S16_LE; break;
				default: StreamInfos.format = A2DPD_PCM_FORMAT_UNKNOWN; break;
				}
				if (send_socket(sockfd, &StreamInfos, sizeof(StreamInfos)) == sizeof(StreamInfos)) {
					a2dp->sk = sockfd;
					syslog(LOG_INFO, "Connected a2dp %p, sk %d, fps %f", a2dp, a2dp->sk, a2dp->TimerInfos.fps);
				} else {
					syslog(LOG_WARNING, "Couldn't send stream informations");
					a2dp_disconnect(a2dp);
				}
			} else {
				close_socket(sockfd);
				syslog(LOG_WARNING, "Connected a2dp %p, sk %d, Authorisation failed", a2dp, a2dp->sk);
			}
		} else {
			syslog(LOG_ERR, "Socket failed a2dp %p, sk %d", a2dp, a2dp->sk);
		}
	}
	return 0;
}

static inline snd_pcm_a2dp_t *a2dp_alloc(void)
{
	snd_pcm_a2dp_t *a2dp;
	a2dp = malloc(sizeof(*a2dp));
	if (a2dp) {
		memset(a2dp, 0, sizeof(*a2dp));
		a2dp->sk = -1;
	}
	return a2dp;
}

static inline void a2dp_free(snd_pcm_a2dp_t * a2dp)
{
	a2dp_disconnect(a2dp);
	free(a2dp);
}

static int a2dp_start(snd_pcm_ioplug_t * io)
{
	//snd_pcm_a2dp_t *a2dp = io->private_data;
	//FIXME
	return 0;
}

static int a2dp_stop(snd_pcm_ioplug_t * io)
{
	//snd_pcm_a2dp_t *a2dp = io->private_data;
	return 0;
}

static snd_pcm_sframes_t a2dp_pointer(snd_pcm_ioplug_t * io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	return a2dp->num;
}

// This is the main transfer func which does the transfer and sleep job
static snd_pcm_sframes_t a2dp_transfer2(snd_pcm_ioplug_t * io, char *buf, int32_t datatoread)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	int transfer = 0;

	// Connect if needed and send
	a2dp_connect(a2dp);
	if (transfer >= 0)
		transfer = send_socket(a2dp->sk, &datatoread, sizeof(datatoread));
	if (transfer >= 0)
		transfer = send_socket(a2dp->sk, buf, datatoread);

	// Disconnect if error detected
	if (transfer < 0)
		a2dp_disconnect(a2dp);

	// The data are sent to the daemon that act as a proxy thus we double transfer delay to compensate latency
	a2dp_timer_notifyframe(&a2dp->TimerInfos);
	a2dp_timer_sleep(&a2dp->TimerInfos, 4 * A2DPTIMERPREDELAY);

	// Stats
	if (a2dp->TimerInfos.display > 0) {
		if (errno != 0 || transfer <= 0) {
			syslog(LOG_INFO, "send_socket(%d bytes)=%d (errno=%d:%s)", datatoread, transfer, errno, strerror(errno));
		}
	}
	// update pointer, tell alsa we're done
	a2dp->num += datatoread / a2dp->frame_bytes;

	return datatoread / a2dp->frame_bytes;
}

// also works but sleeps between transfers
// This is the main transfer func which does the transfer and sleep job
static snd_pcm_sframes_t a2dp_transfer_all(snd_pcm_ioplug_t * io, const snd_pcm_channel_area_t * areas, snd_pcm_uframes_t offset, snd_pcm_uframes_t nframes)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	int i = 0;
	snd_pcm_sframes_t totaltransfered = 0;
	while (i++ < 1 && totaltransfered < nframes) {
		char *buf = (char *) areas->addr + (areas->first + areas->step * offset) / 8;
		int datatoread = min(A2DPD_BLOCK_SIZE, nframes * a2dp->frame_bytes);
		snd_pcm_sframes_t transfered = a2dp_transfer2(io, buf, datatoread);
		if (transfered > 0) {
			offset += transfered;
			totaltransfered += transfered;
		} else {
			break;
		}
	}
	return totaltransfered;
}

static int a2dp_close(snd_pcm_ioplug_t * io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	a2dp_disconnect(a2dp);
	a2dp_free(a2dp);
	return 0;
}

static int a2dp_params(snd_pcm_ioplug_t * io, snd_pcm_hw_params_t * params)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	unsigned int period_bytes;

	a2dp->frame_bytes = (snd_pcm_format_physical_width(io->format) * io->channels) / 8;

	period_bytes = io->period_size * a2dp->frame_bytes;

//	DBG("format %s rate %d channels %d", snd_pcm_format_name(io->format), io->rate, io->channels);

//	DBG("frame_bytes %d period_bytes %d period_size %ld buffer_size %ld", a2dp->frame_bytes, period_bytes, io->period_size, io->buffer_size);

	return 0;
}

static int a2dp_prepare(snd_pcm_ioplug_t * io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	a2dp->num = 0;
	a2dp->rate = io->rate;
	a2dp->channels = io->channels;

	a2dp->TimerInfos.fps = (float) ((((float)a2dp->rate) * ((float) a2dp->frame_bytes) / ((float) A2DPD_BLOCK_SIZE)) / 1.0);

	return 0;
}

static int a2dp_drain(snd_pcm_ioplug_t * io)
{
//	snd_pcm_a2dp_t *a2dp = io->private_data;
//	DBG("a2dp %p", a2dp);
	return 0;
}

static int a2dp_descriptors_count(snd_pcm_ioplug_t * io)
{
	return 1;
}

static int a2dp_descriptors(snd_pcm_ioplug_t * io, struct pollfd *pfds, unsigned int space)
{
	if (space < 1) {
//		DBG("Can't fill in descriptors");
		SNDERR("Can't fill in descriptors");
		return 0;
	}
	// Alsa does make sure writing now will not block
	// So give him an always writable socket!
	pfds[0].fd = fileno(stdout);
	pfds[0].events = POLLOUT;
	return 1;
}

static int a2dp_poll(snd_pcm_ioplug_t * io, struct pollfd *pfds, unsigned int nfds, unsigned short *revents)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	*revents = pfds[0].revents;

	if (a2dp->sk <= 0)
		return 0;

	if (pfds[0].revents & POLLHUP) {
		a2dp_disconnect(a2dp);
		snd_pcm_ioplug_reinit_status(&a2dp->io);
	}

	return 0;
}

static snd_pcm_ioplug_callback_t a2dp_callback = {
	.close = a2dp_close,
	.start = a2dp_start,
	.stop = a2dp_stop,
	.prepare = a2dp_prepare,
	.transfer = a2dp_transfer_all,
	.pointer = a2dp_pointer,
	.hw_params = a2dp_params,
	.drain = a2dp_drain,
	.poll_descriptors_count = a2dp_descriptors_count,
	.poll_descriptors = a2dp_descriptors,
	.poll_revents = a2dp_poll,
};

// Alsa can convert about any format/channels/rate to any other rate
// However, since we added some code in the daemon to convert, why not do it ourselves!!!
// Moreover some player like aplay won't play a wav file if the device that do not natively support the requested format
// If you want alsa to do the conversion, just remove the value you want to see converted
static int a2dp_constraint(snd_pcm_a2dp_t * a2dp)
{
	snd_pcm_ioplug_t *io = &a2dp->io;
	#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
	snd_pcm_access_t access_list[] = { SND_PCM_ACCESS_RW_INTERLEAVED };
	unsigned int formats[] = { SND_PCM_FORMAT_U8, SND_PCM_FORMAT_S8, SND_PCM_FORMAT_S16_LE };
	unsigned int channels[] = { 1, 2 };
	unsigned int rates[] = { 8000, 11025, 22050, 32000, 44100, 48000 };
	int formats_nb = ARRAY_SIZE(formats);
	int channels_nb = ARRAY_SIZE(channels);
	int rates_nb = ARRAY_SIZE(rates);
	int rate_daemon = 0;
	int rate_prefered = 0;
	char srcfilename[512];
	int err;

	get_config_filename(srcfilename, sizeof(srcfilename));
	// Default is same as the daemon
	rate_daemon = read_config_int(srcfilename, "a2dpd", "rate", A2DPD_FRAME_RATE);
	// If a value is specified, use it
	rate_prefered = read_config_int(srcfilename, "a2dpd", "plugin-rate", rate_daemon);
	// If this value is not 0, alsa will convert to plugin-rate
	if(rate_prefered != 0) {
		// use defaults settings the rate specified + 16 bits stereo
		rates[0] = rate_prefered;
		rates_nb = 1;
		formats[0] = SND_PCM_FORMAT_S16_LE;
		formats_nb = 1;
		channels[0] = 2;
		channels_nb = 1;
	} else {
		// If this value is 0, the daemon will do most conversions
	}

	syslog(LOG_INFO, "[build %s %s] a2dp %p", __DATE__, __TIME__, a2dp);

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS, ARRAY_SIZE(access_list), access_list);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT, formats_nb, formats);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_CHANNELS, channels_nb, channels);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_RATE, rates_nb, rates);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 8192, 8192);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS, 2, 2);
	if (err < 0)
		return err;

	return 0;
}

SND_PCM_PLUGIN_DEFINE_FUNC(a2dpd)
{
	snd_pcm_a2dp_t *a2dp = NULL;
	snd_config_iterator_t i, next;
	int err = 0;

//	DBG("name %s mode %d", name, mode);

	// set up thread signal handler
	signal(SIGPIPE, sighand);

	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (!strcmp(id, "comment") || !strcmp(id, "type"))
			continue;

		// Ignore old options
		if (strstr("ipaddr bdaddr port src dst use_rfcomm", id))
			continue;

		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	a2dp = a2dp_alloc();
	if (!a2dp) {
		SNDERR("Can't allocate plugin data");
		return -ENOMEM;
	}

	// Notify plugin
	a2dp->io.version = SND_PCM_IOPLUG_VERSION;
	a2dp->io.name = "Bluetooth Advanced Audio Distribution";
	a2dp->io.mmap_rw = 0;
	a2dp->io.callback = &a2dp_callback;
	a2dp->io.private_data = a2dp;

	err = snd_pcm_ioplug_create(&a2dp->io, name, stream, mode);
	if (err < 0)
		goto error;

	err = a2dp_constraint(a2dp);
	if (err < 0) {
		snd_pcm_ioplug_delete(&a2dp->io);
		goto error;
	}

	*pcmp = a2dp->io.pcm;
	return 0;

      error:
	a2dp_disconnect(a2dp);
	a2dp_free(a2dp);

	return err;
}

SND_PCM_PLUGIN_SYMBOL(a2dpd);
