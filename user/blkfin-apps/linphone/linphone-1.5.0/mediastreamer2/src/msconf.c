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

#ifndef CONF_GRAN_MAX
#define CONF_GRAN_MAX 12 /* limit for 'too much data' */
#endif

#ifndef CONF_GRAN
#define CONF_GRAN (160)
#endif
#define CONF_NSAMPLES (CONF_GRAN/2)
#ifndef CONF_MAX_PINS
#define CONF_MAX_PINS 32
#endif

typedef struct Channel{
	MSBufferizer buff;
	int16_t input[CONF_NSAMPLES];
	bool_t has_contributed;
#ifdef AMD_HACK
	bool_t is_used;
	int missed;
	int diff;
#endif
} Channel;

typedef struct ConfState{
	Channel channels[CONF_MAX_PINS];
	int sum[CONF_NSAMPLES];
} ConfState;


static void channel_init(Channel *chan){
	ms_bufferizer_init(&chan->buff);
}

static void channel_uninit(Channel *chan){
	ms_bufferizer_uninit(&chan->buff);
}

static void conf_init(MSFilter *f){
	ConfState *s=ms_new0(ConfState,1);
	int i;
	for (i=0;i<CONF_MAX_PINS;i++)
		channel_init(&s->channels[i]);
	f->data=s;
}

static void conf_uninit(MSFilter *f){
	ConfState *s=(ConfState*)f->data;
	int i;
	for (i=0;i<CONF_MAX_PINS;i++)
		channel_uninit(&s->channels[i]);
	ms_free(f->data);
}

static void conf_preprocess(MSFilter *f){
#ifdef AMD_HACK
	ConfState *s=(ConfState*)f->data;
	int i;
	for (i=0;i<CONF_MAX_PINS;i++)
	  {
	    s->channels[i].is_used=FALSE;
	    s->channels[i].missed=0;
	  }
#endif
}

#ifndef AMD_HACK

static bool_t should_process(MSFilter *f, ConfState *s){
	int i;
	int has_data=0;
	int connected=0;
	Channel *chan;
	bool_t has_too_much_data=FALSE;

	for (i=0;i<CONF_MAX_PINS;++i){
		if (f->inputs[i]!=NULL){
			chan=&s->channels[i];
			++connected;
			if (ms_bufferizer_get_avail(&chan->buff)>=CONF_GRAN)
				++has_data;
			if (ms_bufferizer_get_avail(&chan->buff)>=CONF_GRAN*CONF_GRAN_MAX){
				has_too_much_data=TRUE;
				break;
			}
		}
	}

	return has_too_much_data || (connected==has_data);
}

#else

static bool_t should_process(MSFilter *f, ConfState *s){
	int i;
	int do_process=FALSE;
	int has_data=0;
	int connected=0;
	Channel *chan;
#if 0
	bool_t has_too_much_data=FALSE;
#endif

	if (ms_bufferizer_get_avail(&(&s->channels[0])->buff)>CONF_GRAN
	    && s->channels[0].is_used==FALSE)
	  {
	    /* soundread has just started */
	    s->channels[0].is_used=TRUE;
	  }
	else if (s->channels[0].is_used==FALSE)
	  {
	    return FALSE;
	  }

	/* check wheter streams are used */
	for (i=1;i<CONF_MAX_PINS;++i){
	  if (f->inputs[i]!=NULL && (i%2==1) && s->channels[i].is_used==FALSE){
	    chan=&s->channels[i];
	    if (ms_bufferizer_get_avail(&chan->buff)>=3*CONF_GRAN)
	      {
		int k;
		/* new contributing stream :) */
		ms_message("msconf: new contributing stream %i", i);
		s->channels[i].is_used=TRUE;
		s->channels[i].missed=0;
		
		/* reinitialize checking streams */
		s->channels[i].diff=0;
		for (k=0;k<CONF_MAX_PINS;++k){
		  if (f->inputs[k]!=NULL){
		    chan=&s->channels[k];
		    s->channels[i].diff = ms_bufferizer_get_avail(&chan->buff);
		  }
		}
	      }
	  }
	}

	/* decide wheter to process or not */
	if (ms_bufferizer_get_avail(&(&s->channels[0])->buff)<CONF_GRAN)
	  {
	    do_process=FALSE;
	  }
	else if (ms_bufferizer_get_avail(&(&s->channels[0])->buff)>=CONF_GRAN*CONF_GRAN_MAX)
	  {
	    do_process=TRUE;


	    /* disable streams that are not contributing any more */
	    for (i=1;i<CONF_MAX_PINS;++i){
	      if (f->inputs[i]!=NULL && (i%2==1) && s->channels[i].is_used==TRUE){
		chan=&s->channels[i];
		if (ms_bufferizer_get_avail(&chan->buff)<CONF_GRAN)
		  s->channels[i].missed++;
		if (ms_bufferizer_get_avail(&chan->buff)<CONF_GRAN
		    && s->channels[i].missed==4)
		  {
		    /* delete from contributing stream :( */
		    s->channels[i].is_used=FALSE;
		    s->channels[i].missed=0;
		    ms_message("msconf: contributing stream deleted %i", i);
		  }
	      }
	    }
	    
	  }
	else
	  {
	    /* if a stream is_used, then check its availability.
	       if a stream !is_used, then don't check it.
	       only check RTP incoming stream pins.
	    */
	    for (i=1;i<CONF_MAX_PINS;++i){
	      if (f->inputs[i]!=NULL && (i%2==1) && s->channels[i].is_used==TRUE){
 		chan=&s->channels[i];
		++connected;
		if (ms_bufferizer_get_avail(&chan->buff)>=CONF_GRAN)
		  ++has_data;
		}
	    }
	    if (connected==has_data)
		do_process=TRUE;
	  }

	if (do_process==TRUE && s->channels[0].missed==500)
	  {
	    s->channels[0].missed=0;
	    /* compare incoming and soundread streams */
	    for (i=1;i<CONF_MAX_PINS;++i){
	      if (f->inputs[i]!=NULL && (i%2==1) && s->channels[i].is_used==TRUE){
		int new_diff;
		int old_diff;
		chan=&s->channels[i];
		old_diff = s->channels[0].diff - s->channels[i].diff;
		new_diff = ms_bufferizer_get_avail(&s->channels[0].buff) - ms_bufferizer_get_avail(&s->channels[i].buff);
		if (new_diff-old_diff>(CONF_GRAN*2))
		  {
		    ms_message("msconf: missing data from contributing stream", new_diff-old_diff);
		  }
		else if (old_diff-new_diff>(CONF_GRAN*2))
		  {
		    int xtra_data = ms_bufferizer_get_avail(&chan->buff) - 6*CONF_GRAN;
		    int k=0;
		    if (xtra_data>0)
		      {
			while (ms_bufferizer_get_avail(&chan->buff)>CONF_GRAN*6)
			  {
			    k++;
			    ms_bufferizer_read(&chan->buff,(uint8_t*)chan->input,CONF_GRAN);
			  }
		      }
		    ms_message("msconf: extra data from contributing stream %i", old_diff-new_diff, k*CONF_GRAN);
		    
		  }
	      }
	    } 
	  }
	else if (do_process==TRUE)
	  s->channels[0].missed++;


	return (do_process==TRUE);
#if 0
	/* case where: every one has enough data */
	if (ms_bufferizer_get_avail(&(&s->channels[0])->buff)<CONF_GRAN)
	  {
	    return FALSE;
	  }
	if (ms_bufferizer_get_avail(&(&s->channels[0])->buff)>=CONF_GRAN*CONF_GRAN_MAX)
	  {
	    for (i=1;i<CONF_MAX_PINS;++i){
	      if (f->inputs[i]!=NULL && (i%2==1)){
		chan=&s->channels[i];
		++connected;
		if (ms_bufferizer_get_avail(&chan->buff)>=CONF_GRAN)
		  ++has_data;
		if (ms_bufferizer_get_avail(&chan->buff)>=CONF_GRAN*CONF_GRAN_MAX){
		  has_too_much_data=TRUE;
		  break;
		}
	      }
	    }

	    /* don't wait for missing incoming RTP packets */
	    /* return has_too_much_data || (connected==has_data); */
	    return TRUE;
	  }


	/* The conversation timing HAS TO BE driven by soundread wich is
	   the best clock we can found.

	   To make the whole process obey this clock, the decision to
	   process data for conference is decided by pin0 (soundread).
	*/

	if (s->is_starting==TRUE)
	  {
	    /* we don't want to wait for incoming stream before
	       we send outgoing stream! */
	    
	    for (i=1;i<CONF_MAX_PINS;++i){
	      if (f->inputs[i]!=NULL && (i%2==1)){
		chan=&s->channels[i];
		if (ms_bufferizer_get_avail(&chan->buff)>=CONF_GRAN)
		  {
		    s->is_starting=FALSE;
		    break;
		  }
	      }
	    }
	    if (ms_bufferizer_get_avail(&(&s->channels[0])->buff)>=CONF_GRAN)
	      {
		return TRUE;
	      }
	    return FALSE;
	  }

	if (has_too_much_data==TRUE)
	{
		int discarded_data;
		chan=&s->channels[0];
		discarded_data = ms_bufferizer_get_avail(&chan->buff);
		/* check if the inputs provide enough data */
		if (discarded_data>=CONF_GRAN*CONF_GRAN_MAX)
		{
			while (ms_bufferizer_get_avail(&chan->buff)>CONF_GRAN*4)
			{
				ms_bufferizer_read(&chan->buff,(uint8_t*)chan->input,CONF_GRAN);
			}
			ms_message("msconf: data from soundread -> (%i discarded)", discarded_data - ms_bufferizer_get_avail(&chan->buff));

			for (i=1;i<CONF_MAX_PINS;i=i+2){
				if (f->inputs[i]!=NULL){
					chan=&s->channels[i];
					discarded_data = ms_bufferizer_get_avail(&chan->buff);
					while (ms_bufferizer_get_avail(&chan->buff)>CONF_GRAN*4)
					{
						ms_bufferizer_read(&chan->buff,(uint8_t*)chan->input,CONF_GRAN);
					}
					ms_message("msconf: data from channel%i -> (%i discarded)", i, discarded_data - ms_bufferizer_get_avail(&chan->buff));
				}
			}
		}
		else
		{
			for (i=1;i<CONF_MAX_PINS;i=i+2){
				if (f->inputs[i]!=NULL){
					chan=&s->channels[i];
					discarded_data = ms_bufferizer_get_avail(&chan->buff);
					if (discarded_data>=CONF_GRAN*CONF_GRAN_MAX)
					{
						while (ms_bufferizer_get_avail(&chan->buff)>CONF_GRAN*4)
						{
							ms_bufferizer_read(&chan->buff,(uint8_t*)chan->input,CONF_GRAN);
						}
						ms_message("msconf: data from channel%i -> (%i discarded)", i, discarded_data - ms_bufferizer_get_avail(&chan->buff));
					}
				}
			}
		}
	}

	return has_too_much_data || (connected==has_data);
#endif
}

#endif

static void conf_sum(ConfState *s){
	int i,j;
	Channel *chan;
	memset(s->sum,0,CONF_NSAMPLES*sizeof(int));
	for (i=0;i<CONF_MAX_PINS;++i){
		chan=&s->channels[i];
		if (ms_bufferizer_read(&chan->buff,(uint8_t*)chan->input,CONF_GRAN)
			==CONF_GRAN){
			for(j=0;j<CONF_NSAMPLES;++j){
				s->sum[j]+=chan->input[j];
			}
			chan->has_contributed=TRUE;
		}else{
			chan->has_contributed=FALSE;
		}
	}
}

static inline int16_t saturate(int sample){
	if (sample>32000)
		sample=32000;
	else if (sample<-32000)
		sample=-32000;
	return (int16_t)sample;
}

static mblk_t * conf_output(ConfState *s, Channel *chan){
	mblk_t *m=allocb(CONF_GRAN,0);
	int i;
	int tmp;
	if (chan->has_contributed==TRUE){
		for (i=0;i<CONF_NSAMPLES;++i){
			tmp=s->sum[i]-(int)chan->input[i];
			*((int16_t*)m->b_wptr)=saturate(tmp);
			m->b_wptr+=2;
		}
	}else{
		for (i=0;i<CONF_NSAMPLES;++i){
			tmp=s->sum[i];
			*((int16_t*)m->b_wptr)=saturate(tmp);
			m->b_wptr+=2;
		}
	}
	return m;
}

static void conf_dispatch(MSFilter *f, ConfState *s){
	int i;
	Channel *chan;
	mblk_t *m;
	//memset(s->sum,0,CONF_NSAMPLES*sizeof(int));
	for (i=0;i<CONF_MAX_PINS;++i){
		if (f->outputs[i]!=NULL){
			chan=&s->channels[i];
			m=conf_output(s,chan);
			ms_queue_put(f->outputs[i],m);
		}
	}
}

static void conf_process(MSFilter *f){
	int i;
	ConfState *s=(ConfState*)f->data;
	Channel *chan;
	/*read from all inputs and put into bufferizers*/
	for (i=0;i<CONF_MAX_PINS;++i){
		if (f->inputs[i]!=NULL){
			chan=&s->channels[i];
			ms_bufferizer_put_from_queue(&chan->buff,f->inputs[i]);
		}
	}

	/*do the job */
	while(should_process(f,s)==TRUE){
		conf_sum(s);
		conf_dispatch(f,s);
	}
}

#ifdef _MSC_VER

MSFilterDesc ms_conf_desc={
	MS_CONF_ID,
	"MSConf",
	"A filter to make conferencing",
	MS_FILTER_OTHER,
	NULL,
	CONF_MAX_PINS,
	CONF_MAX_PINS,
	conf_init,
	conf_preprocess,
	conf_process,
	NULL,
	conf_uninit,
	NULL
};

#else

MSFilterDesc ms_conf_desc={
	.id=MS_CONF_ID,
	.name="MSConf",
	.text="A filter to make conferencing",
	.category=MS_FILTER_OTHER,
	.ninputs=CONF_MAX_PINS,
	.noutputs=CONF_MAX_PINS,
	.init=conf_init,
	.preprocess=conf_preprocess,
	.process=conf_process,
	.uninit=conf_uninit,
};

#endif

MS_FILTER_DESC_EXPORT(ms_conf_desc)
