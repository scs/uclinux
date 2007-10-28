/*      $Id: hw_audio.c,v 5.2 2005/07/10 08:34:11 lirc Exp $      */

/****************************************************************************
 ** hw_audio.c **************************************************************
 ****************************************************************************
 *
 * routines for using a IR receiver in microphone input using portaudio library
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 * Copyright (C) 2001, 2002 Pavel Machek <pavel@ucw.cz>
 * Copyright (C) 2002 Matthias Ringwald <ringwald@inf.ethz.ch>
 *
 * Distribute under GPL version 2 or later.
 *
 * Using ... hardware ... 
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"
#include "transmit.h"
#include "hw_default.h"

static int ptyfd;        /* the pty */

/* PortAudio Includes */
#include <portaudio.h>

#define SAMPLE_RATE  (44100)
#define NUM_CHANNELS    (2)
#define DITHER_FLAG     (0) /**/

/* Select sample format. */
#define PA_SAMPLE_TYPE  paUInt8
typedef unsigned char SAMPLE;

typedef struct
{
	int				lastFrames[3];
	int				lastSign;
	int				pulseSign;
	unsigned int	lastCount;
}
paTestData;

PortAudioStream *stream;


extern struct ir_remote *repeat_remote;
extern struct rbuf rec_buffer;

char ptyName[256];
int master;


int myfd = -1;

void addCode( lirc_t data)
{
	write( master, &data, sizeof( lirc_t ) );
}

/* This routine will be called by the PortAudio engine when audio is needed.
** It may be called at interrupt level on some machines so don't do anything
** that could mess up the system like calling malloc() or free().
*/

static int recordCallback( void *inputBuffer, void *outputBuffer,
                           unsigned long framesPerBuffer,
                           PaTimestamp outTime, void *userData )
{
	paTestData *data = (paTestData*)userData;
	SAMPLE *rptr = (SAMPLE*)inputBuffer;
	long i;

	SAMPLE	*myPtr = rptr;

	unsigned int time;
	int samplerate = SAMPLE_RATE;
	int	diff;

	(void) outputBuffer; /* Prevent unused variable warnings. */
	(void) outTime;

	for ( i=0; i < framesPerBuffer; i++, myPtr++)
	{
		/* New Algo */
		diff = abs(data->lastFrames[0] - *myPtr);
		if ( diff > 100)
		{
			if (data->pulseSign == 0)
			{
				// we got the first signal, this is a PULSE
				if ( *myPtr > data->lastFrames[0] )
				{
					data->pulseSign = 1;
				} 
				else
				{
					data->pulseSign = -1;
				}
			}

			if (data->lastCount > 0)
			{
				if ( *myPtr > data->lastFrames[0] && data->lastSign <= 0)
				{
					// printf("CHANGE ++ ");
					data->lastSign = 1;
	
					time = data->lastCount * 1000000 / samplerate;
					if (data->lastSign == data->pulseSign)
					{
						addCode( time );
						// printf("Pause: %d us, %d \n", time, data->lastCount);
					}
					else
					{
						addCode( time | PULSE_BIT );
						// printf("Pulse: %d us, %d \n", time, data->lastCount);
					}
					data->lastCount = 0;
				}
				
				else if (  *myPtr < data->lastFrames[0] && data->lastSign >= 0)
				{
					// printf("CHANGE -- ");
					data->lastSign = -1;
	
					time = data->lastCount * 1000000 / samplerate;
					if (data->lastSign == data->pulseSign)
					{
						// printf("Pause: %d us, %d \n", time, data->lastCount);
						addCode( time );
					}
					else
					{
						// printf("Pulse: %d us, %d \n", time, data->lastCount);
						addCode( time | PULSE_BIT);
					}data->lastCount = 0;
				}
			}
		}

		if ( data->lastCount < 100000 )
		{
			data->lastCount++;
		}

		data->lastFrames[0] = data->lastFrames[1];
		data->lastFrames[1] = *myPtr;
		
		// skip 2. channel
		if (NUM_CHANNELS == 2)
			myPtr++;
	}
	return 0;
}

/*
  decoding stuff
*/

#define BUFSIZE 20
#define SAMPLE 47999


lirc_t audio_readdata(lirc_t timeout)
{
	lirc_t data;
	int ret;

	if (!waitfordata((long) timeout))
		return 0;

	ret=read(hw.fd,&data,sizeof(data));
	if(ret!=sizeof(data))
	{
		LOGPRINTF(1,"error reading from lirc");
		LOGPERROR(1,NULL);
		dosigterm(SIGTERM);
	}
	return(data);
}


/*
  interface functions
*/
paTestData data;

int audio_init()
{

	PaError    err;
	int 		flags;
	struct termios	t;

	LOGPRINTF(1,"hw_audio_init()");
	
	// 
	logprintf(LOG_INFO,"Initializing %s...",hw.device);
	init_rec_buffer();
	rewind_rec_buffer();
	
	// new
	data.lastFrames[0] = 128;
	data.lastFrames[1] = 128;
	data.lastFrames[2] = 128;
	data.lastSign = 0;
	data.lastCount = 0;
	data.pulseSign = 0;
	
	err = Pa_Initialize();
	if( err != paNoError ) goto error;

	// Record some audio. --------------------------------------------
	err = Pa_OpenStream
		(
		 &stream,
		 Pa_GetDefaultInputDeviceID(),
		 NUM_CHANNELS,               // stereo input
		 PA_SAMPLE_TYPE,
		 NULL,
		 paNoDevice,
		 0,
		 PA_SAMPLE_TYPE,
		 NULL,
		 SAMPLE_RATE,
		 512,             // frames per buffer 
		 0,               // number of buffers, if zero then use default minimum 
		 0, 			   // flags 
		 recordCallback,
		 &data );

	if( err != paNoError ) goto error;

	// open pty
	if ( openpty( &master, &ptyfd, ptyName, 0, 0) == -1)
	{
		logprintf(LOG_ERR,"openpty failed");
		logperror(LOG_ERR,"openpty()");
		goto error;
	}
	
	// regular device file
	if( tcgetattr( master, &t ) < 0 ) {
		logprintf(LOG_ERR,"tcgetattr failed");
		logperror(LOG_ERR,"tcgetattr()");
	}
	
	cfmakeraw( &t );
	
	// apply file descriptor options
	if( tcsetattr( master, TCSANOW, &t ) < 0) {  
		logprintf(LOG_ERR,"tcsetattr failed");
		logperror(LOG_ERR,"tcsetattr()");
	}

	flags=fcntl(ptyfd,F_GETFL,0);
	if(flags!=-1)
	{
		fcntl(ptyfd,F_SETFL,flags|O_NONBLOCK);
	}

	LOGPRINTF(LOG_INFO,"PTY name: %s", ptyName);

	hw.fd=ptyfd;

	err = Pa_StartStream( stream );
	if( err != paNoError ) goto error;

	return(1);

 error:
	Pa_Terminate();
	logprintf(LOG_ERR, "an error occured while using the portaudio stream" );
	logprintf(LOG_ERR, "error number: %d", err );
	logprintf(LOG_ERR, "error message: %s", Pa_GetErrorText( err ) );

	return (0);
}

int audio_deinit(void)
{
	PaError    err;

	LOGPRINTF(1,"hw_audio_deinit()");
	
	// close port audio
	err = Pa_CloseStream( stream );
	if( err != paNoError ) goto error;

	Pa_Terminate();
	
	// wair for terminaton
	usleep(20000);

	// close pty
	close(master);
	close(ptyfd);
	
	return 1;

 error:
	Pa_Terminate();
	logprintf(LOG_ERR,
		  "an error occured while using the portaudio stream");
	logprintf(LOG_ERR,"error number: %d",err);
	logprintf(LOG_ERR,"eError message: %s",Pa_GetErrorText(err));
	return 0;
}

char *audio_rec(struct ir_remote *remotes)
{
	if(!clear_rec_buffer()) return(NULL);
	return(decode_all(remotes));
}

int audio_decode(struct ir_remote *remote,
		   ir_code *prep,ir_code *codep,ir_code *postp,
		   int *repeat_flagp,lirc_t *remaining_gapp)
{
	return(receive_decode(remote,prep,codep,postp,
			      repeat_flagp,remaining_gapp));
}


struct hardware hw_audio=
{
	"pty",	    /* simple device */
	-1,                 /* fd */
	LIRC_CAN_REC_MODE2, /* features */
	0,                  /* send_mode */
	LIRC_MODE_MODE2,    /* rec_mode */
	0,                  /* code_length */
	audio_init,         /* init_func */
	NULL,		    /* config_func */
	audio_deinit,       /* deinit_func */
	NULL,		    /* send_func */
	audio_rec,          /* rec_func */
	audio_decode,       /* decode_func */
	NULL,               /* ioctl_func */
	audio_readdata,
	"audio"
};
