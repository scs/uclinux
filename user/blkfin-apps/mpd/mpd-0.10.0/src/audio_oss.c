/* the Music Player Daemon (MPD)
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 *
 * OSS audio output (c) 2004 by Eric Wong <eric@petta-tech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "audio.h"

#ifdef HAVE_OSS

#include "conf.h"
#include "log.h"
#include "sig_handlers.h"

#include <string.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>

#ifdef HAVE_AUDIO

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#if defined(__OpenBSD__) || defined(__NetBSD__)
# include <soundcard.h>
#else /* !(defined(__OpenBSD__) || defined(__NetBSD__) */
# include <sys/soundcard.h>
#endif /* !(defined(__OpenBSD__) || defined(__NetBSD__) */

static int audio_write_size; /*= 16*1026*2; */

static AudioFormat audio_format;

int audio_device = 0;

#endif /* HAVE_AUDIO */

static AudioFormat * audio_configFormat = NULL;

static void copyAudioFormat(AudioFormat * dest, AudioFormat * src) {
        dest->sampleRate = src->sampleRate;
        dest->bits = src->bits;
        dest->channels = src->channels;
}

void initAudioDriver() {
	char * test;
	audio_write_size = strtol((getConf())[CONF_AUDIO_WRITE_SIZE],&test,10);
	if (*test!='\0') {
		ERROR("\"%s\" is not a valid write size",
			(getConf())[CONF_AUDIO_WRITE_SIZE]);
		exit(EXIT_FAILURE);
	}
}

void getOutputAudioFormat(AudioFormat * inAudioFormat, 
                AudioFormat * outAudioFormat)
{
        if (audio_configFormat)
                copyAudioFormat(outAudioFormat,audio_configFormat);
        else
		copyAudioFormat(outAudioFormat,inAudioFormat);
}

void initAudioConfig() {
        char * conf = getConf()[CONF_AUDIO_OUTPUT_FORMAT];
        char * test;

        if(NULL == conf) return;

        audio_configFormat = malloc(sizeof(AudioFormat));

        memset(audio_configFormat,0,sizeof(AudioFormat));

        audio_configFormat->sampleRate = strtol(conf,&test,10);
       
        if(*test!=':') {
                ERROR("error parsing audio output format: %s\n",conf);
                exit(EXIT_FAILURE);
        }
 
        /*switch(audio_configFormat->sampleRate) {
        case 48000:
        case 44100:
        case 32000:
        case 16000:
                break;
        default:
                ERROR("sample rate %i can not be used for audio output\n",
                        (int)audio_configFormat->sampleRate);
                exit(EXIT_FAILURE);
        }*/

        if(audio_configFormat->sampleRate <= 0) {
                ERROR("sample rate %i is not >= 0\n",
                                (int)audio_configFormat->sampleRate);
                exit(EXIT_FAILURE);
        }

        audio_configFormat->bits = strtol(test+1,&test,10);
        
        if(*test!=':') {
                ERROR("error parsing audio output format: %s\n",conf);
                exit(EXIT_FAILURE);
        }

        switch(audio_configFormat->bits) {
        case 16:
                break;
        default:
                ERROR("bits %i can not be used for audio output\n",
                        (int)audio_configFormat->bits);
                exit(EXIT_FAILURE);
        }

        audio_configFormat->channels = strtol(test+1,&test,10);
        
        if(*test!='\0') {
                ERROR("error parsing audio output format: %s\n",conf);
                exit(EXIT_FAILURE);
        }

        switch(audio_configFormat->channels) {
        case 2:
                break;
        default:
                ERROR("channels %i can not be used for audio output\n",
                        (int)audio_configFormat->channels);
                exit(EXIT_FAILURE);
        }
}

void finishAudioConfig() {
        if(audio_configFormat) free(audio_configFormat);
}

void finishAudioDriver() {
	/* empty */
}

int isCurrentAudioFormat(AudioFormat * audioFormat) {
#ifdef HAVE_AUDIO
	if(!audio_device || !audioFormat) return 0;

	if(memcmp(audioFormat,&audio_format,sizeof(AudioFormat)) != 0) return 0;
#endif
	return 1;
}

int openAudioDevice(AudioFormat * audioFormat) {
#ifdef HAVE_AUDIO
	int i = AFMT_S16_LE, err = 0;
	if (audio_device && !isCurrentAudioFormat(audioFormat)) 
		closeAudioDevice();
	if (audio_device!=0)
		return 0;
	
	if (audioFormat)
		copyAudioFormat(&audio_format,audioFormat);

	blockSignals();
	audio_device = open("/dev/dsp", O_WRONLY);
	
	if (audio_device < 0) err |= 1;
	
	if (ioctl(audio_device,SNDCTL_DSP_SETFMT,&i))
		err |= 2;
	i = audio_format.channels;
	if (ioctl(audio_device,SNDCTL_DSP_CHANNELS, &i))
		err |= 4;
	i = audio_format.sampleRate;
	if (ioctl(audio_device,SNDCTL_DSP_SPEED,&i))
		err |= 8;
	i = audio_format.bits;
	if (ioctl(audio_device,SNDCTL_DSP_SAMPLESIZE,&i))
		err |= 16;
	/*i = 1; if (ioctl(audio_device,SNDCTL_DSP_STEREO,&i)) err != 32; */
	
	unblockSignals();
	
	if (err)
		ERROR("Error opening /dev/dsp: 0x%x\n");
	if (!audio_device)
		return -1;
#endif
	return 0;
}

int playAudio(char * playChunk, int size) {
#ifdef HAVE_AUDIO
	if(audio_device==0) {
		ERROR("trying to play w/o the audio device being open!\n");
		return -1;
	}
	while (size > 0) {
		int send = audio_write_size>size?size:audio_write_size;
		int ret = write(audio_device,playChunk,send);
		if(ret<0) {
			audioError();
			ERROR("closing audio device due to write error\n");
			closeAudioDevice();
			return -1;
		}
		playChunk+=ret;
		size-=ret;
	}

#endif
	return 0;
}

int isAudioDeviceOpen() {
#ifdef HAVE_AUDIO
	if(audio_device) return 1;
#endif
	return 0;
}

void closeAudioDevice() {
#ifdef HAVE_AUDIO
	if(audio_device) {
		blockSignals();
		close(audio_device);
		audio_device = 0;
		unblockSignals();
	}
#endif
}

void audioError() {
#ifdef HAVE_AUDIO
	ERROR("%s: errno: %i\n",__func__,errno);
#endif
}

#endif /* !HAVE_OSS */


