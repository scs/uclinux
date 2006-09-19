/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include <speex/speex_preprocess.h>

#include "mediastreamer2/mssndcard.h"
#include "mediastreamer2/msfilter.h"

#ifdef WIN32
#include <malloc.h> /* for alloca */
#endif

#include <mmsystem.h>
#ifdef _MSC_VER
#include <mmreg.h>
#endif
#include <msacm.h>

MSFilter *ms_winsnd_read_new(MSSndCard *card);
MSFilter *ms_winsnd_write_new(MSSndCard *card);

typedef struct WinSndData{
	char *pcmdev;
	char *mixdev;

    int sound_err;
    WAVEFORMATEX wfx;
    WAVEHDR waveouthdr[30];
    char waveoutbuffer[30][3200];
    HWAVEOUT waveoutdev;
    int buffer_playing;

    WAVEHDR waveinhdr[30];
    HWAVEIN waveindev;
    char waveinbuffer[30][3200];

    int rate;
	int bits;
	ms_thread_t thread;
	ms_mutex_t mutex;
	queue_t rq;
	MSBufferizer * bufferizer;
	bool_t read_started;
	bool_t write_started;
	bool_t stereo;

	SpeexPreprocessState *pst;
} WinSndData;

static void CALLBACK
SpeakerCallback (HWAVEOUT _waveoutdev, UINT uMsg, DWORD dwInstance,
                 DWORD dwParam1, DWORD dwParam2)
{
  WAVEHDR *wHdr;
  WinSndData *device;

  switch (uMsg)
    {
      case WOM_OPEN:
          ms_message("SpeakerCallback : WOM_OPEN");
        break;
      case WOM_CLOSE:
          ms_message("SpeakerCallback : WOM_CLOSE");
        break;
      case WOM_DONE:
        wHdr = (WAVEHDR *) dwParam1;
        device = (WinSndData *)dwInstance;
        device->buffer_playing--;
        break;
      default:
        break;
    }
}

static void CALLBACK
WaveInCallback (HWAVEIN waveindev, UINT uMsg, DWORD dwInstance, DWORD dwParam1,
                DWORD dwParam2)
{
  WAVEHDR *wHdr;
  MMRESULT mr = NOERROR;
  WinSndData *device;

  device = (WinSndData *)dwInstance;

  switch (uMsg)
    {
      case MM_WOM_DONE:
        wHdr = (WAVEHDR *) dwParam1;
        /* A waveform-audio data block has been played and 
           can now be freed. */
        ms_message("WaveInCallback : MM_WOM_DONE");
        waveInUnprepareHeader (waveindev, (LPWAVEHDR) wHdr, sizeof (WAVEHDR));
        break;

      case WIM_OPEN:
        ms_message("WaveInCallback : WIM_OPEN");
        break;
      case WIM_CLOSE:
        ms_message("WaveInCallback : WIM_CLOSE");
        break;
      case WIM_DATA:
        wHdr = (WAVEHDR *) dwParam1;

        if (!device->read_started && !device->write_started)
          {
            mr = waveInUnprepareHeader (device->waveindev, (LPWAVEHDR) wHdr, sizeof (WAVEHDR));
            ms_warning("WaveInCallback : unprepare header (waveInUnprepareHeader:0x%i)", mr);
            return;
          }

        if (wHdr->dwBufferLength!=wHdr->dwBytesRecorded)
        {
            mr = waveInAddBuffer (device->waveindev,
                wHdr,
                sizeof (device->waveinhdr[wHdr->dwUser]));
            if (mr != MMSYSERR_NOERROR)
            {
                ms_warning("WaveInCallback : error adding buffer to sound card (waveInAddBuffer:0x%i)", mr);
            }
            return;
        }


    	ms_mutex_lock(&device->mutex);
		if (device->read_started)
        {
			int vad;
            mblk_t *rm=NULL;
            if (rm==NULL) rm=allocb(wHdr->dwBufferLength,0);
			memcpy(rm->b_wptr,wHdr->lpData, wHdr->dwBufferLength);

			if (device->pst!=NULL)
			{
				//memset(rm->b_wptr,0, wHdr->dwBufferLength);

				vad = speex_preprocess(device->pst, (short*)rm->b_wptr, NULL);
#if 0
				if (vad!=1)
		            ms_message("WaveInCallback : %d", vad);
#endif
			}

			rm->b_wptr+=wHdr->dwBufferLength;
		    
			putq(&device->rq,rm);
		    rm=NULL;
        }
    	ms_mutex_unlock(&device->mutex);

        mr = waveInAddBuffer (device->waveindev,
            wHdr,
            sizeof (device->waveinhdr[wHdr->dwUser]));
        if (mr != MMSYSERR_NOERROR)
        {
            ms_warning("WaveInCallback : error adding buffer to sound card (waveInAddBuffer:0x%i)", mr);
            return;
        }
    }
}

static int winsnd_open(WinSndData *device, int devnumber, int bits,int stereo, int rate, int *minsz)
{
    MMRESULT mr = NOERROR;
    DWORD dwFlag;
    int i;
    int channel = 1;
    if (stereo>0)
        channel = stereo;
	device->wfx.wFormatTag = WAVE_FORMAT_PCM;
	device->wfx.cbSize = 0;
	device->wfx.nAvgBytesPerSec = 16000;
	device->wfx.nBlockAlign = 2;
	device->wfx.nChannels = channel;
	device->wfx.nSamplesPerSec = rate; /* 8000; */
	device->wfx.wBitsPerSample = bits;
	
    dwFlag = CALLBACK_FUNCTION;
    if (devnumber != WAVE_MAPPER)
        dwFlag = WAVE_MAPPED | CALLBACK_FUNCTION;
    mr = waveOutOpen (&(device->waveoutdev), devnumber, &(device->wfx), (DWORD) SpeakerCallback,
                    (DWORD)device, dwFlag);
    if (mr != NOERROR)
    {
        ms_warning("Failed to open device: trying default device. (waveOutOpen:0x%i)", mr);
        dwFlag = CALLBACK_FUNCTION;
        mr = waveOutOpen (&(device->waveoutdev), WAVE_MAPPER, &(device->wfx), (DWORD) SpeakerCallback,
                        (DWORD)device, dwFlag);
    }
    if (mr != NOERROR)
    {
        ms_warning("Failed to open windows sound device. (waveOutOpen:0x%i)", mr);
        return -1;
    }

    /* prepare windows buffers */


    for (i = 0; i < 6; i++)
    {
        memset (&(device->waveouthdr[i]), 0, sizeof (device->waveouthdr[i]));
        device->waveouthdr[i].lpData = device->waveoutbuffer[i];
        /* BUG: on ne connait pas la taille des frames a recevoir... 
        on utilise enc_frame_per_packet au lien de dec_frame_per_packet */

        device->waveouthdr[i].dwBufferLength = device->rate/8000 * 320;
        /* 480 pour 98 (speex) */
        device->waveouthdr[i].dwFlags = 0;
        device->waveouthdr[i].dwUser = i;

        mr = waveOutPrepareHeader (device->waveoutdev, &(device->waveouthdr[i]),
            sizeof (device->waveouthdr[i]));
        if (mr != MMSYSERR_NOERROR){
            ms_warning("Failed to prepare windows sound device. (waveOutPrepareHeader:0x%i)", mr);
        }
        else
        {
            ms_message("Sound Header prepared %i for windows sound device. (waveOutPrepareHeader)", i);
        }
    }


    /* Init Microphone device */
    dwFlag = CALLBACK_FUNCTION;
    if (devnumber != WAVE_MAPPER)
        dwFlag = WAVE_MAPPED | CALLBACK_FUNCTION;
    mr = waveInOpen (&(device->waveindev), devnumber, &(device->wfx),
                (DWORD) WaveInCallback, (DWORD)device, dwFlag);
    if (mr != NOERROR)
    {
        ms_warning("Failed to open device: trying default device. (waveInOpen:0x%i)", mr);
        dwFlag = CALLBACK_FUNCTION;
        mr = waveInOpen (&(device->waveindev), WAVE_MAPPER, &(device->wfx),
                    (DWORD) WaveInCallback, (DWORD)device, dwFlag);
    }

    if (mr != NOERROR)
    {
        ms_warning("Failed to prepare windows sound device. (waveInOpen:0x%i)", mr);
        return -1;
    }



    for (i = 0; i < 6; i++)
    {
        memset (&(device->waveinhdr[i]), 0, sizeof (device->waveinhdr[i]));
        device->waveinhdr[i].lpData = device->waveinbuffer[i];
        /* frameSize */
        device->waveinhdr[i].dwBufferLength = device->rate/8000 * 320;
        device->waveinhdr[i].dwFlags = 0;
        device->waveinhdr[i].dwUser = i;
        mr = waveInPrepareHeader (device->waveindev, &(device->waveinhdr[i]),             
            sizeof (device->waveinhdr[i]));
        if (mr == MMSYSERR_NOERROR){
            mr = waveInAddBuffer (device->waveindev, &(device->waveinhdr[i]),
                sizeof (device->waveinhdr[i]));
            if (mr == MMSYSERR_NOERROR)
            {
                ms_message("Sound Header prepared %i for windows sound device. (waveInAddBuffer)", i);
            }
            else
            {
                ms_warning("Failed to prepare windows sound device. (waveInAddBuffer:0x%i)", mr);
            }
        }
        else
        {
            ms_warning("Failed to prepare windows sound device. (waveInPrepareHeader:0x%i)", mr);
        }
    }

#if 0
	device->pst = speex_preprocess_state_init((device->rate/8000 * 320)/2, device->rate);
	if (device->pst!=NULL) {
		float f;
		i=1;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_VAD, &i);
		i=1;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_DENOISE, &i);
		i=0;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_AGC, &i);
		f=8000;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_AGC_LEVEL, &f);
		i=0;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_DEREVERB, &i);
		f=.4;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_DEREVERB_DECAY, &f);
		f=.3;
		speex_preprocess_ctl(device->pst, SPEEX_PREPROCESS_SET_DEREVERB_LEVEL, &f);
	}
#endif

	mr = waveInStart (device->waveindev);
    if (mr != MMSYSERR_NOERROR)
    {
        ms_warning("Failed to start recording on windows sound device. (waveInStart:0x%i)", mr);
        return -1;
    }

	*minsz=device->rate/8000 * 320;
	return 0;
}

static void winsnd_set_level(MSSndCard *card, MSSndCardMixerElem e, int percent)
{
	WinSndData *d=(WinSndData*)card->data;
    MMRESULT mr = NOERROR;
    DWORD dwVolume = 0xFFFF;
    dwVolume = ((0xFFFF) * percent) / 100;

	if (d->mixdev==NULL) return;
	switch(e){
		case MS_SND_CARD_MASTER:
            mr = waveOutSetVolume(d->waveoutdev, dwVolume);
	        if (mr != MMSYSERR_NOERROR)
	        {
                ms_warning("Failed to set master volume. (waveOutSetVolume:0x%i)", mr);
                return;
	        }
            return;
        break;
#if 0
        case MS_SND_CARD_CAPTURE:
			wincmd=SOUND_MIXER_IGAIN;
		break;
		case MS_SND_CARD_PLAYBACK:
			wincmd=SOUND_MIXER_PCM;
		break;
#endif
        default:
			ms_warning("winsnd_card_set_level: unsupported command.");
			return;
	}
}

static int winsnd_get_level(MSSndCard *card, MSSndCardMixerElem e)
{
	WinSndData *d=(WinSndData*)card->data;
    MMRESULT mr = NOERROR;
    DWORD dwVolume = 0x0000;

	if (d->mixdev==NULL) return -1;
	switch(e){
		case MS_SND_CARD_MASTER:
            mr=waveOutGetVolume(d->waveoutdev, &dwVolume);
            // Transform to 0 to 100 scale
            //dwVolume = (dwVolume *100) / (0xFFFF);
            return 60;
        break;
#if 0
        case MS_SND_CARD_CAPTURE:
			osscmd=SOUND_MIXER_IGAIN;
		break;
		case MS_SND_CARD_PLAYBACK:
			osscmd=SOUND_MIXER_PCM;
		break;
#endif
		default:
			ms_warning("winsnd_card_get_level: unsupported command.");
			return -1;
	}
	return -1;
}

static void winsnd_set_source(MSSndCard *card, MSSndCardCapture source)
{
	WinSndData *d=(WinSndData*)card->data;
	if (d->mixdev==NULL) return;

	switch(source){
		case MS_SND_CARD_MIC:
		break;
		case MS_SND_CARD_LINE:
		break;
	}	
}

static void winsnd_init(MSSndCard *card){
	WinSndData *d=ms_new(WinSndData,1);
    memset(d, 0, sizeof(WinSndData));
	d->pcmdev=NULL;
	d->mixdev=NULL;
    d->sound_err=-1; /* not opened */
	d->read_started=FALSE;
	d->write_started=FALSE;
	d->bits=16;
	d->rate=8000;
	d->stereo=FALSE;
	qinit(&d->rq);
	d->bufferizer=ms_bufferizer_new();
	ms_mutex_init(&d->mutex,NULL);
	card->data=d;
	d->pst=0;
}

static void winsnd_uninit(MSSndCard *card){
	WinSndData *d=(WinSndData*)card->data;
	if (d==NULL)
		return;
	if (d->pcmdev!=NULL) ms_free(d->pcmdev);
	if (d->mixdev!=NULL) ms_free(d->mixdev);
	ms_bufferizer_destroy(d->bufferizer);
	flushq(&d->rq,0);

	ms_mutex_destroy(&d->mutex);

	if (d->pst!=NULL)
	    speex_preprocess_state_destroy(d->pst);

	ms_free(d);
}

#define DSP_NAME "/dev/dsp"
#define MIXER_NAME "/dev/mixer"

static void winsnd_detect(MSSndCardManager *m);

MSSndCardDesc winsnd_card_desc={
	"WINSND",
	winsnd_detect,
	winsnd_init,
	winsnd_set_level,
	winsnd_get_level,
	winsnd_set_source,
	ms_winsnd_read_new,
	ms_winsnd_write_new,
	winsnd_uninit
};

static MSSndCard *winsnd_card_new(const char *pcmdev, const char *mixdev){
	MSSndCard *card=ms_snd_card_new(&winsnd_card_desc);
	WinSndData *d=(WinSndData*)card->data;
	d->pcmdev=ms_strdup(pcmdev);
	d->mixdev=ms_strdup(mixdev);
	card->name=ms_strdup(pcmdev);
	return card;
}

static void winsnd_detect(MSSndCardManager *m){
    MMRESULT mr = NOERROR;
    unsigned int nInDevices = waveInGetNumDevs ();
    /*unsigned int nOutDevices = waveOutGetNumDevs ();*/
    unsigned int item;
	char pcmdev[1024];
	char mixdev[1024];

    for (item = 0; item < nInDevices; item++)
    {
        WAVEINCAPS caps;
        mr = waveInGetDevCaps (item, &caps, sizeof (WAVEINCAPS));
        if (mr == MMSYSERR_NOERROR)
        {
            MSSndCard *card;
	        snprintf(pcmdev,sizeof(pcmdev),"%s",caps.szPname);
	        snprintf(mixdev,sizeof(mixdev),"%s",caps.szPname);
            if (item == 0)
            {
		        card=winsnd_card_new(pcmdev,mixdev);
		        ms_snd_card_manager_add_card(m,card);
            }
			card=winsnd_card_new(pcmdev,mixdev);
			ms_snd_card_manager_add_card(m,card);
        }
    }
}

static void * winsnd_thread(void *p){
	MSSndCard *card=(MSSndCard*)p;
	WinSndData *d=(WinSndData*)card->data;
	int bsize=0;
	uint8_t *rtmpbuff=NULL;
	uint8_t *wtmpbuff=NULL;
	int err;
#if 0
	mblk_t *rm=NULL;
#endif

    MMRESULT mr = NOERROR;
    int pos_whdr=0;

	d->sound_err=winsnd_open(d, 0, d->bits,d->stereo,d->rate,&bsize);
	if (d->sound_err==0){
		rtmpbuff=(uint8_t*)alloca(bsize);
		wtmpbuff=(uint8_t*)alloca(bsize);
	}
	while(d->read_started || d->write_started){
		if (d->sound_err==0){
#if 0
			if (d->read_started){
                if (rm==NULL) rm=allocb(bsize,0);

                /* get data from callback */
				//err=read(d->pcmfd,rm->b_wptr,bsize);
                err=-1;

				if (err<0){
					ms_warning("Fail to read %i bytes from soundcard: %s",
					bsize,strerror(errno));
				}else{
					rm->b_wptr+=err;
					putq(&d->rq,rm);
					rm=NULL;
				}
			}else {
				int sz;
                //sz = read(d->pcmfd,rtmpbuff,bsize);
                sz=-1;
				if( sz!=bsize) ms_warning("sound device read returned %i !",sz);
			}
#endif
			if (d->write_started){

                if (d->buffer_playing<3)
                {
					/* remove extra buffer when latency is increasing:
					this often happen with USB device */
					ms_mutex_lock(&d->mutex);
					if (d->bufferizer->size>=bsize*(7-d->buffer_playing)){
                        ms_warning("Extra data for sound card removed (%ims)", (d->bufferizer->size*20)/320);
					    err=ms_bufferizer_read(d->bufferizer,wtmpbuff,bsize);
					    err=ms_bufferizer_read(d->bufferizer,wtmpbuff,bsize);
					}
				    err=ms_bufferizer_read(d->bufferizer,wtmpbuff,bsize);
					ms_mutex_unlock(&d->mutex);
				    if (err==bsize){

                        /* write to sound devide! */
                        //err=write(d->pcmfd,wtmpbuff,bsize);
                        memcpy (d->waveouthdr[pos_whdr].lpData, wtmpbuff, bsize);

                        mr = waveOutWrite (d->waveoutdev,
                            &(d->waveouthdr[pos_whdr]),
                            sizeof (d->waveouthdr[pos_whdr]));

                        if (mr != MMSYSERR_NOERROR)
                        {
                            if (mr == WAVERR_STILLPLAYING)
                            {
                                /* retry later */
                                /* data should go back to queue */
                                /* TODO */
                                ms_warning("sound device write STILL_PLAYING (waveOutWrite:0x%i)", mr);
                            }
                            else
                            {
                                ms_warning("sound device write returned (waveOutWrite:0x%i)", mr);
                            }
                        }
                        else
                        {
                            d->buffer_playing++;
                            pos_whdr++;
                            if (pos_whdr == 6)
                                pos_whdr = 0;   /* loop over the prepared blocks */
                        }


					    if (err<0){
						    ms_warning("Fail to write %i bytes from soundcard: %s",
						    bsize,strerror(errno));
					    }
				    }
                }
                else
                {
					ms_mutex_lock(&d->mutex);
					if (d->bufferizer->size>=bsize*4){
                        ms_warning("Extra data for sound card removed (%ims)", (d->bufferizer->size*20)/320);
					    err=ms_bufferizer_read(d->bufferizer,wtmpbuff,bsize);
					    err=ms_bufferizer_read(d->bufferizer,wtmpbuff,bsize);
					    err=ms_bufferizer_read(d->bufferizer,wtmpbuff,bsize);
					}
					ms_mutex_unlock(&d->mutex);
                    Sleep(10);
                }
			}else {
                if (d->buffer_playing<3)
                {
				    memset(wtmpbuff,0,bsize);
    				
                    memcpy (d->waveouthdr[pos_whdr].lpData, wtmpbuff, bsize);
                    //sz = write(d->pcmfd,wtmpbuff,bsize);
                    mr = waveOutWrite (d->waveoutdev,
                        &(d->waveouthdr[pos_whdr]),
                        sizeof (d->waveouthdr[pos_whdr]));

                    if (mr != MMSYSERR_NOERROR)
                    {
                        if (mr == WAVERR_STILLPLAYING)
                        {
                            /* retry later */
                            /* data should go back to queue */
                            /* TODO */
                            ms_warning("sound device write STILL_PLAYING (waveOutWrite:0x%i)", mr);
                        }
                        else
                        {
                            ms_warning("sound device write returned (waveOutWrite:0x%i)", mr);
                        }
                    }
                    else
                    {
                        d->buffer_playing++;
                        pos_whdr++;
                        if (pos_whdr == 6)
                            pos_whdr = 0;   /* loop over the prepared blocks */
                    }
			    }
                else
                {
                    Sleep(10);
                }
            }
		}else Sleep(10);
	}
	if (d->sound_err==0) {
        int i;
        int count=0;
        /* close sound card */

        /* unprepare buffer */
        for (i = 0; i < 6; i++)
        {
            int counttry=0;
            for (counttry=0;counttry<10;counttry++)
            {
                mr = waveInUnprepareHeader (d->waveindev,
                                        &(d->waveinhdr[i]),
                                        sizeof (d->waveinhdr[i]));
                if (mr != MMSYSERR_NOERROR)
                {
                    ms_error("Failed to unprepared %i buffer from sound card (waveInUnprepareHeader:0x%i", count, mr);
                    Sleep (200);
                } else
                {
                    count++;
        		    ms_message("successfully unprepared %i buffer from sound card.", count);
                    break;
                }
            }
        }
		ms_warning("unprepared %i buffer from sound card.", count);

        mr = waveInStop (d->waveindev);
        if (mr != MMSYSERR_NOERROR)
        {
        	ms_error("failed to stop recording sound card (waveInStop:0x%i)", mr);
        } else
        {
        	ms_message("successfully stopped recording sound card");
        }

        mr = waveInReset (d->waveindev);
        if (mr != MMSYSERR_NOERROR)
        {
        	ms_warning("failed to reset recording sound card (waveInReset:0x%i)", mr);
        } else
        {
        	ms_message("successful reset of recording sound card");
        }

        mr = waveInClose (d->waveindev);
        if (mr != MMSYSERR_NOERROR)
        {
        	ms_warning("failed to close recording sound card (waveInClose:0x%i)", mr);
        } else
        {
        	ms_message("successfully closed recording sound card");
        }
		d->sound_err=-1;
	}
	return NULL;
}

static void winsnd_start_r(MSSndCard *card){
	WinSndData *d=(WinSndData*)card->data;
	if (d->read_started==FALSE && d->write_started==FALSE){
		d->read_started=TRUE;
		ms_thread_create(&d->thread,NULL,winsnd_thread,card);
	}else d->read_started=TRUE;
}

static void winsnd_stop_r(MSSndCard *card){
	WinSndData *d=(WinSndData*)card->data;
	d->read_started=FALSE;
	if (d->write_started==FALSE){
		ms_thread_join(d->thread,NULL);
	}
}

static void winsnd_start_w(MSSndCard *card){
	WinSndData *d=(WinSndData*)card->data;
	if (d->read_started==FALSE && d->write_started==FALSE){
		d->write_started=TRUE;
		ms_thread_create(&d->thread,NULL,winsnd_thread,card);
	}else{
		d->write_started=TRUE;
	}
}

static void winsnd_stop_w(MSSndCard *card){
	WinSndData *d=(WinSndData*)card->data;
	d->write_started=FALSE;
	if (d->read_started==FALSE){
		ms_thread_join(d->thread,NULL);
	}
}

static mblk_t *winsnd_get(MSSndCard *card){
	WinSndData *d=(WinSndData*)card->data;
	mblk_t *m;
	ms_mutex_lock(&d->mutex);
	m=getq(&d->rq);
	ms_mutex_unlock(&d->mutex);
	return m;
}

static void winsnd_put(MSSndCard *card, mblk_t *m){
	WinSndData *d=(WinSndData*)card->data;
	ms_mutex_lock(&d->mutex);
	ms_bufferizer_put(d->bufferizer,m);
	ms_mutex_unlock(&d->mutex);
}


static void winsnd_read_preprocess(MSFilter *f){
	MSSndCard *card=(MSSndCard*)f->data;
	winsnd_start_r(card);
}

static void winsnd_read_postprocess(MSFilter *f){
	MSSndCard *card=(MSSndCard*)f->data;
	winsnd_stop_r(card);
}

static void winsnd_read_process(MSFilter *f){
	MSSndCard *card=(MSSndCard*)f->data;
	mblk_t *m;
	while((m=winsnd_get(card))!=NULL){
		ms_queue_put(f->outputs[0],m);
	}
}

static void winsnd_write_preprocess(MSFilter *f){
	MSSndCard *card=(MSSndCard*)f->data;
	winsnd_start_w(card);
}

static void winsnd_write_postprocess(MSFilter *f){
	MSSndCard *card=(MSSndCard*)f->data;
	winsnd_stop_w(card);
}

static void winsnd_write_process(MSFilter *f){
	MSSndCard *card=(MSSndCard*)f->data;
	mblk_t *m;
	while((m=ms_queue_get(f->inputs[0]))!=NULL){
		winsnd_put(card,m);
	}
}

static int set_rate(MSFilter *f, void *arg){
	MSSndCard *card=(MSSndCard*)f->data;
	WinSndData *d=(WinSndData*)card->data;
	d->rate=*((int*)arg);
	return 0;
}

static int set_nchannels(MSFilter *f, void *arg){
	MSSndCard *card=(MSSndCard*)f->data;
	WinSndData *d=(WinSndData*)card->data;
	d->stereo=(*((int*)arg)==2);
	return 0;
}

static MSFilterMethod winsnd_methods[]={
	{	MS_FILTER_SET_SAMPLE_RATE	, set_rate	},
	{	MS_FILTER_SET_NCHANNELS		, set_nchannels	},
	{	0				, NULL		}
};

MSFilterDesc winsnd_read_desc={
	MS_WINSND_READ_ID,
	"MSWinSndRead",
	"Sound capture filter for Windows Sound drivers",
	MS_FILTER_OTHER,
	NULL,
    0,
	1,
	NULL,
    winsnd_read_preprocess,
	winsnd_read_process,
	winsnd_read_postprocess,
    NULL,
	winsnd_methods
};


MSFilterDesc winsnd_write_desc={
	MS_WINSND_WRITE_ID,
	"MSWinSndWrite",
	"Sound playback filter for Windows Sound drivers",
	MS_FILTER_OTHER,
	NULL,
    1,
	0,
	NULL,
    winsnd_write_preprocess,
	winsnd_write_process,
	winsnd_write_postprocess,
	NULL,
    winsnd_methods
};

MSFilter *ms_winsnd_read_new(MSSndCard *card){
	MSFilter *f=ms_filter_new_from_desc(&winsnd_read_desc);
	f->data=card;
	return f;
}


MSFilter *ms_winsnd_write_new(MSSndCard *card){
	MSFilter *f=ms_filter_new_from_desc(&winsnd_write_desc);
	f->data=card;
	return f;
}

MS_FILTER_DESC_EXPORT(winsnd_read_desc)
MS_FILTER_DESC_EXPORT(winsnd_write_desc)
