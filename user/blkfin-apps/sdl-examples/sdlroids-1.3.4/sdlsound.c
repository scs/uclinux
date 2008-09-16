/* 
 * SDLRoids - An Astroids clone.
 * 
 * Copyright (c) 2000 David Hedbor <david@hedbor.org>
 * 	based on xhyperoid by Russel Marks.
 * 	xhyperoid is based on a Win16 game, Hyperoid by Edward Hutchins 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 */

/*
 * sdlsound.c - Sound playing routines using raw SDL or SDL_mixer.
 */

#include "config.h"
RCSID("$Id: sdlsound.c,v 1.10 2001/03/24 04:04:06 neotron Exp $");

#include "SDL_audio.h"
#include "sdlsound.h"
#include "misc.h"
#include "roidsupp.h"

#ifdef HAVE_LIBSDL_MIXER
# ifdef HAVE_SDL_MIXER_H
#  include "SDL_mixer.h"
#  define USE_SDL_MIXER
# else
#  ifdef HAVE_SDL_SDL_MIXER_H
#   include "SDL/SDL_mixer.h"
#   define USE_SDL_MIXER
#  endif
# endif
#endif

#include <stdlib.h>

static int use_audio;

/* sample filenames */
static char *samplename[]=
{
  "sounds/pshot.wav",
  "sounds/thrust.wav",
  "sounds/explode.wav",
  "sounds/explode2.wav",
  "sounds/bshot.wav",
  "sounds/phit.wav",
  "sounds/title.wav",
  "sounds/newbonus.wav",
  "sounds/newbad.wav",
  "sounds/bonusgot.wav",
  "sounds/bwound.wav",
  "sounds/swarmsplit.wav"
};

#ifndef USE_SDL_MIXER

struct channel_tag
{
  struct sample_tag *sample;	/* pointer to sample struct, NULL if none */
  int offset;			/* position in sample */
  int loop;                     /* loop the sound */
} channel[NUM_CHANNELS];


/* for in-memory samples */
struct sample_tag
{
  SDL_AudioSpec spec; /* Sample format spec */
  Uint8 *data; /* Data buffer */
  Uint32 len;  /* buffer length */
} samples[NUM_SAMPLES];

#define BYTEFIX(x)	(((x)<0)?0:(((x)>255)?255:(x)))

/* mix and play a chunk of sound to /dev/dsp. */

void play_audio(void *udata, Uint8 *stream, int len)
{
  int f,g,v;
  struct channel_tag *cptr;
  Uint8 soundbuf[1024];
  if(udata == NULL) return;
  for(f = 0; f < len; f++)
  {
    v=0;
    for(g = 0, cptr = &(channel[0]); g < NUM_CHANNELS; g++, cptr++)
      if(cptr->sample != NULL)
      {
	v += (int)cptr->sample->data[ cptr->offset++ ];
	if(cptr->offset >= cptr->sample->len) {
	  if(cptr->loop == 1) {
	    cptr->offset = 0;
	  } else
	    cptr->sample = NULL;
	}
      }
      else
	v+=128;	/* make sure it doesn't click! */
  
    /* kludge to up the volume of sound effects - mmm, lovely distortion :-) */
    v -= 128*NUM_CHANNELS;
    v = 128 + (v * 3) / (2 * NUM_CHANNELS);
    v = BYTEFIX(v);
  
    soundbuf[f] = (unsigned char)v;
  }
  SDL_MixAudio(stream, soundbuf, len, SDL_MIX_MAXVOLUME);

}

/* Load the specified sample */
int load_sample(int num) {
  
  if(SDL_LoadWAV(samplename[num], &samples[num].spec,
		 &samples[num].data, &samples[num].len) ||
     SDL_LoadWAV(datafilename(NULL, samplename[num]), &samples[num].spec,
		   &samples[num].data, &samples[num].len) || 
     SDL_LoadWAV(datafilename(DATADIR, samplename[num]), &samples[num].spec,
		   &samples[num].data, &samples[num].len) || 
     SDL_LoadWAV(datafilename(bindir, samplename[num]), &samples[num].spec,
		   &samples[num].data, &samples[num].len))
    return 1;
  return 0;
}

void init_sound(void)
{
  int f;
  SDL_AudioSpec wanted;
  /* Set the audio format */
  wanted.freq = 8000;
  wanted.format = AUDIO_U8;
  wanted.channels = 1;    /* 1 = mono, 2 = stereo */
  wanted.samples = 1024;  /* Good low-latency value for callback */
  wanted.callback = play_audio;
  wanted.userdata = NULL;
  
  if( SDL_OpenAudio(&wanted, NULL) < 0) {
    fprintf(stderr, "Warning: %s\n", SDL_GetError());
    use_audio=0;
    return;
  } else
    use_audio=1;
  memset(channel, 0, sizeof(channel));
  for(f = 0; f < NUM_SAMPLES; f++)
  {
    if(!load_sample(f)) {
      fprintf(stderr, "Fatal: Couldn't load sample %s.\n", samplename[f]);
      exit(1);
    }
  }
}

/* setup a new sample to be played on a given channel. */
void queuesam(int chan,int sam)
{
  if(!use_audio) return;
  SDL_PauseAudio(1);
  channel[chan].sample = &samples[sam];
  channel[chan].offset = 0;
  channel[chan].loop   = 0;
  SDL_PauseAudio(0);
}

void loopsam(int chan,int sam)
{
  if(!use_audio) return;
  SDL_PauseAudio(1);
  if(sam >=0 ) {
    channel[chan].sample = &samples[sam];
    channel[chan].offset = 0;
    channel[chan].loop   = 1;
  } else {
    channel[chan].sample = NULL;
    channel[chan].offset = 0;
    channel[chan].loop   = 0;
  }
  SDL_PauseAudio(0);
}

void exit_sound()
{
  int f;
  if(!use_audio) return;

  for(f = 0; f < NUM_SAMPLES; f++)
    SDL_FreeWAV(samples[f].data);
}

#else /*USE_SDL_MIXER */

/* for in-memory samples */
static Mix_Chunk *samples[NUM_SAMPLES];

/* Load the specified sample */
int load_sample(int num) {
  
  if((samples[num] = Mix_LoadWAV(samplename[num])) ||
     Mix_LoadWAV(datafilename(NULL, samplename[num])) || 
     Mix_LoadWAV(datafilename(DATADIR, samplename[num])) || 
     Mix_LoadWAV(datafilename(bindir, samplename[num])))
    return 1;
  return 0;
}

void init_sound(void)
{
  int f;
  int audio_rate, audio_channels;
  Uint16 audio_format;

  /* Set the audio format */
  audio_rate = 8000;
  audio_format = AUDIO_S16;
  audio_channels = 2;    /* 1 = mono, 2 = stereo */

  if (Mix_OpenAudio(audio_rate, audio_format, audio_channels, 256) < 0) {
    fprintf(stderr, "Warning: %s\n", SDL_GetError());
    use_audio = 0;
    return;
  }  else {
    Mix_QuerySpec(&audio_rate, &audio_format, &audio_channels);
    use_audio = 1;
  }
  for(f = 0; f < NUM_CHANNELS; f++) Mix_Volume(f, 100);

  for(f = 0; f < NUM_SAMPLES; f++)
  {
    if(!load_sample(f))
    {
      fprintf(stderr, "Fatal: Couldn't load sample %s.\n", samplename[f]);
      exit(1);
    }
  }
}

void exit_sound()
{
  int f;
  if(!use_audio) return;

  for(f = 0; f < NUM_SAMPLES; f++)
    Mix_FreeChunk(samples[f]);
}

/* setup a new sample to be played on a given channel. */
void queuesam(int chan,int sam)
{
  if(!use_audio) return;
  Mix_PlayChannel(chan, samples[sam], 0);
}


/* setup a new sample to be played on a given channel. */
void loopsam(int chan,int sam)
{
  if(!use_audio) return;
  if(sam >=0 )
    Mix_PlayChannel(chan, samples[sam], -1);
  else
    Mix_HaltChannel(chan);
}

#endif

