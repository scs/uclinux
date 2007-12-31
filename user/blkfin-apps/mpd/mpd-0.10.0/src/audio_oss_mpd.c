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


#include "audio_mpd.h"

#ifdef HAVE_OSS

#include "conf.h"
#include "log.h"
#include "sig_handlers.h"

#include <string.h>
#include <assert.h>
#include <signal.h>

#include <stdlib.h>

/* HACK until I figure out the autotools stuff, I compile with --disable-audio - eric */
#define HAVE_AUDIO 1
#include <playerData.h>
#ifdef HAVE_AUDIO
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>
#include <unistd.h>
#include <errno.h>

static int audio_write_size=4096; /*= 16*1026*2; */

static AudioFormat audio_format;

int audio_device = 0;
//int ogg_file= 0;

#endif
char silence[CHUNK_SIZE];

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
	fprintf(stderr,"Writing to the audio_device function \n");

	audio_device = open("/dev/dsp", O_RDWR);
	
	if (audio_device < 0) err |= 1;

        if (ioctl(audio_device, SNDCTL_DSP_RESET, 0) == -1) {
                ERROR("Error (SNDCTL_DSP_RESET)");
                err |=1;
        }

        if (ioctl(audio_device, SNDCTL_DSP_SYNC, 0) == -1) {
                ERROR("Error (SNDCTL_DSP_SYNC)");
                err |=1;
        }

	if (ioctl(audio_device,SNDCTL_DSP_SETFMT,&i))
		err |= 2;
	if (ioctl(audio_device,SNDCTL_DSP_CHANNELS, &audio_format.channels))
		err |= 4;
	if (ioctl(audio_device,SNDCTL_DSP_SPEED,&audio_format.sampleRate))
		err |= 8;
	if (ioctl(audio_device,SNDCTL_DSP_SAMPLESIZE,&audio_format.bits))
		err |= 16;
	i = 1; if (ioctl(audio_device,SNDCTL_DSP_STEREO,&i)) err != 32; 
	
	unblockSignals();
	
	if (err)
		ERROR("Error opening /dev/dsp: 0x%x\n");
	if (!audio_device)
		return -1;

//**********************************************
//	fprintf(stderr,"Writing to the ogg_file \n");

//	ogg_file = open("/mnt/oggf",O_RDWR|O_CREAT);
//	ogg_file = open("/var/oggf", O_RDWR );		//for reading from the created file oggf
	
//	if(ogg_file < 0)
//	{
//		fprintf(stderr,"Error opening the ogg_file \n");
//	}	
//**********************************************/
#endif
	return 0;
}

int playAudio(char * playChunk, int size) {
#ifdef HAVE_AUDIO
	char buf[66000];	
	int send;
	int ret;
	
	if(audio_device==0) {
		ERROR("trying to play w/o the audio device being open!\n");
		return -1;
	}
	//send = audio_write_size>size?size:audio_write_size;
	//******************************
//	read(ogg_file,buf,size);   // reading from the oggf file
	//fprintf(stderr,"Reading from the ogg_file [k %d]\n",);
	
	//***************************
	send = size;
	while (size > 0) {
		fprintf(stderr,"****************In the audio_oss_mpd.c [size %d]\n",size);
 
//		ret = write(audio_device,buf,send);
		ret = write(audio_device,playChunk,send);

	//************************************
//		write(ogg_file,playChunk,send);
	//**********************************	

		if(ret<0) {
			audioError();
			ERROR("closing audio device due to write error\n");
			closeAudioDevice();
			return -1;
		}
		playChunk+=ret;
		size-=ret;
		fprintf(stderr,"exiting from the playaudio Function\n");
//***************************
//		memset(buf,0,sizeof(buf));
//*************************
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
//*******************
//		close(ogg_file);
//		ogg_file=0;
//**********************
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


// Code by ganapathi , used by sivaraman

extern  void doIOForInterfaces();
extern void addInterfacesReadyToReadAndListenSocketToFdSet(fd_set * fds, int * fdmax);
void lookup(void)
{
	extern int fdmax;
        fd_set rfds;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 1;
	fdmax=0;
	addInterfacesReadyToReadAndListenSocketToFdSet(&rfds,&fdmax);

        if(select(fdmax+1,&rfds,NULL,NULL,&tv)) {
        doIOForInterfaces();
	}
}
//Code by sivaraman, used for pause
int playSilence(void)
{
	memset(silence,0,CHUNK_SIZE);
	if(playAudio(silence, CHUNK_SIZE) < 0) return -1;

return 0;
}

