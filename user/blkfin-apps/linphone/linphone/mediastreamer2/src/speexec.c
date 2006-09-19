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

#include "mediastreamer2/msfilter.h"

#include <speex/speex_echo.h>
#include <speex/speex_preprocess.h>

#include "mediastreamer-config.h"

#ifdef WIN32
#include <malloc.h> /* for alloca */
#endif

#ifdef TEST_AEC
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

static const int framesize=128;
static const int filter_length=2048; /*250 ms*/

typedef struct SpeexECState{
	SpeexEchoState *ecstate;
	MSBufferizer in[2];
	int framesize;
	SpeexPreprocessState *den;
        int ref;
        int echo;
        int out;
}SpeexECState;

#if 0
struct adataptedstate {
   int frame_size;           /**< Number of samples processed each time */
   int window_size;
   int M;
   int cancel_count;
   int adapted;
};
#endif

static void speex_ec_init(MSFilter *f){
	SpeexECState *s=ms_new(SpeexECState,1);
	s->framesize=framesize;
	ms_bufferizer_init(&s->in[0]);
	ms_bufferizer_init(&s->in[1]);
	s->ecstate=speex_echo_state_init(s->framesize,filter_length);
	f->data=s;

	s->den = speex_preprocess_state_init(s->framesize, 8000);
#ifdef TEST_AEC
	s->ref=-1;
	s->echo=-1;
	s->out=-1;
	s->ref=open("aec_ref.wav",O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	s->echo=open("aec_echo.wav",O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	s->out=open("aec_out.wav",O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
#endif

}

static void speex_ec_uninit(MSFilter *f){
	SpeexECState *s=(SpeexECState*)f->data;
	ms_bufferizer_uninit(&s->in[0]);
	ms_bufferizer_uninit(&s->in[1]);
	speex_echo_state_destroy(s->ecstate);
	if (s->den!=NULL)
	  speex_preprocess_state_destroy(s->den);

#ifdef TEST_AEC
	if (s->ref!=-1)
	  close(s->ref);
	if (s->echo!=-1)
	  close(s->echo);
	if (s->out!=-1)
	  close(s->out);
#endif
	ms_free(s);
}

/*	inputs[0]= reference signal (sent to soundcard)
	inputs[1]= echo signal	(read from soundcard)
*/


static void speex_ec_process(MSFilter *f){
	SpeexECState *s=(SpeexECState*)f->data;
	int nbytes=s->framesize*2;
	uint8_t *in1;
	mblk_t *om0,*om1;
//#ifdef HAVE_SPEEX_NOISE
//	spx_int32_t *noise=(spx_int32_t*)alloca(nbytes*sizeof(spx_int32_t)+1);
//#else
//	float *noise=NULL;
//#endif

	/*read input and put in bufferizers*/
	ms_bufferizer_put_from_queue(&s->in[0],f->inputs[0]);
	ms_bufferizer_put_from_queue(&s->in[1],f->inputs[1]);
	
	in1=(uint8_t*)alloca(nbytes);

	ms_debug("speexec:  in0=%i, in1=%i",ms_bufferizer_get_avail(&s->in[0]),ms_bufferizer_get_avail(&s->in[1]));

	if (ms_bufferizer_get_avail(&s->in[0])> 320 * 6) /* above 250ms -> useless */
	  {
	    /* reset evrything */
	    ms_warning("speexec: -reset of echo canceller- in0=%i, in1=%i",ms_bufferizer_get_avail(&s->in[0]),ms_bufferizer_get_avail(&s->in[1]));
	    flushq(&s->in[1].q,0);
	    flushq(&s->in[0].q,0);
	    ms_bufferizer_init(&s->in[0]);
	    ms_bufferizer_init(&s->in[1]);
            speex_echo_state_reset(s->ecstate);
	  }

	while (ms_bufferizer_get_avail(&s->in[0])>=nbytes && ms_bufferizer_get_avail(&s->in[1])>=nbytes){
		om0=allocb(nbytes,0);
		ms_bufferizer_read(&s->in[0],(uint8_t*)om0->b_wptr,nbytes);
		/* we have reference signal */
		/* the reference signal is sent through outputs[0]*/
		
		om0->b_wptr+=nbytes;
		ms_queue_put(f->outputs[0],om0);

		ms_bufferizer_read(&s->in[1],in1,nbytes);
		/* we have echo signal */
		om1=allocb(nbytes,0);
		speex_echo_cancel(s->ecstate,(short*)in1,(short*)om0->b_rptr,(short*)om1->b_wptr,NULL);
//		if (s->den!=NULL && noise!=NULL)
//		  speex_preprocess(s->den, (short*)om1->b_wptr, noise);
#ifdef TEST_AEC
		if (s->ref!=-1 && s->echo!=-1 && s->out!=-1)
		  {
		    write(s->ref,in1,nbytes);
		    write(s->echo,om0->b_rptr,nbytes);
		    write(s->out,om1->b_wptr,nbytes);
		  }
#endif
#if 0
		{
			static int adapted=0;
			static int nonadapted=0;
			struct adataptedstate *_adaptedstate=(struct adataptedstate *)s->ecstate;
			if (_adaptedstate->adapted)
				adapted++;
			else
				nonadapted++;
			if (adapted%100==1)
				ms_message("adapted 100 times");
			if (nonadapted%100==1)
				ms_message("nonadapted 100 times");
		}
#endif

		om1->b_wptr+=nbytes;
		ms_queue_put(f->outputs[1],om1);
		
	}
	while (ms_bufferizer_get_avail(&s->in[1])>2*nbytes){
		om1=allocb(nbytes,0);
		ms_bufferizer_read(&s->in[1],(uint8_t*)om1->b_wptr,nbytes);
		om1->b_wptr+=nbytes;
		ms_queue_put(f->outputs[1],om1);
		ms_message("too much echo signal, sending anyway.");
		speex_echo_state_reset(s->ecstate);
	}
	
}

#ifdef _MSC_VER

MSFilterDesc ms_speex_ec_desc={
	MS_SPEEX_EC_ID,
	"MSSpeexEC",
	"Echo canceler using speex library",
	MS_FILTER_OTHER,
	NULL,
	2,
	2,
	speex_ec_init,
	NULL,
	speex_ec_process,
	NULL,
	speex_ec_uninit,
	NULL
};

#else

MSFilterDesc ms_speex_ec_desc={
	.id=MS_SPEEX_EC_ID,
	.name="MSSpeexEC",
	.text="Echo canceler using speex library",
	.category=MS_FILTER_OTHER,
	.ninputs=2,
	.noutputs=2,
	.init=speex_ec_init,
	.process=speex_ec_process,
	.uninit=speex_ec_uninit
};

#endif

MS_FILTER_DESC_EXPORT(ms_speex_ec_desc)
