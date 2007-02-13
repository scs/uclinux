/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2001  Simon MORLAT simon.morlat@linphone.org

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
/***************************************************************************
 *            jitterctl.c
 *
 *  Mon Nov  8 11:53:21 2004
 *  Copyright  2004  Simon MORLAT
 *  Email simon.morlat@linphone.org
 ****************************************************************************/

#include "ortp/rtpsession.h"
#include "ortp/payloadtype.h"
#include "ortp/ortp.h"
#include "utils.h"
#include <math.h>

#define JC_BETA 0.03	/*allows a clock slide around 3% */
#define JC_GAMMA (JC_BETA)

#include "jitterctl.h"

void jitter_control_init(JitterControl *ctl, int base_jiitt_time, PayloadType *payload){
	ctl->count=0;
	ctl->slide=0;
	ctl->jitter=0;
	ctl->inter_jitter=0;
	ctl->slide=0;
	if (base_jiitt_time!=-1) ctl->jitt_comp = base_jiitt_time;
	/* convert in timestamp unit: */
	if (payload!=NULL){
		jitter_control_set_payload(ctl,payload);
	}
	ctl->adapt_jitt_comp_ts=ctl->jitt_comp_ts;
	ctl->corrective_slide=0;
}

void jitter_control_enable_adaptive(JitterControl *ctl, bool_t val){
	ctl->adaptive=val;
}

void jitter_control_set_payload(JitterControl *ctl, PayloadType *pt){
	ctl->jitt_comp_ts =
			(int) (((double) ctl->jitt_comp / 1000.0) * (pt->clock_rate));
	ctl->corrective_step=(160 * 8000 )/pt->clock_rate; /* This formula got to me after some beers */
	ctl->adapt_jitt_comp_ts=ctl->jitt_comp_ts;
}


void jitter_control_dump_stats(JitterControl *ctl){
	ortp_message("JitterControl:\n\tslide=%g,jitter=%g,count=%i",
			ctl->slide,ctl->jitter, ctl->count);
}


void jitter_control_update_corrective_slide(JitterControl *ctl){
	int tmp;
	tmp=(int)(ctl->slide)-ctl->corrective_slide;
	if (tmp>ctl->corrective_step) ctl->corrective_slide+=ctl->corrective_step;
	else if (tmp<-ctl->corrective_step) ctl->corrective_slide-=ctl->corrective_step;
}

/*
 The algorithm computes two values:
	slide: an average of difference between the expected and the socket-received timestamp
	jitter: an average of the absolute value of the difference between socket-received timestamp and slide.
	slide is used to make clock-slide detection and correction.
	jitter is added to the initial jitt_comp_time value. It compensates bursty packets arrival (packets
	not arriving at regular interval ).
*/
void jitter_control_new_packet(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts, int32_t * slide, int32_t *safe_delay){
	int diff=packet_ts - cur_str_ts;
	float gap;
	int d;
	//printf("diff=%g\n",diff);
	
	ctl->count++;
	ctl->slide= (float) ((ctl->slide*(1-JC_BETA)) + ((float)diff*JC_BETA));
	gap=(float) fabs((float)diff - ctl->slide);
	ctl->jitter=(float) ((ctl->jitter*(1-JC_GAMMA)) + (gap*JC_GAMMA));
	d=diff-ctl->olddiff;
	ctl->inter_jitter=(float) (ctl->inter_jitter+ (( (float)abs(d) - ctl->inter_jitter)*(1/16.0)));
	ctl->olddiff=diff;
	if (ctl->adaptive){
		if (ctl->count%50==0) {
			/*jitter_control_dump_stats(ctl);*/
		}
		/* the following is nearly equivalent, but maybe it consumes more CPU: ?*/
		/*ctl->corrective_slide=(((int)ctl->slide)/ctl->corrective_step)*ctl->corrective_step;*/
		
		ctl->adapt_jitt_comp_ts=(int) MAX(ctl->jitt_comp_ts,ctl->jitter);
		
		*slide=(int32_t)ctl->slide;
		*safe_delay=(int32_t)ctl->adapt_jitt_comp_ts;
	}else {
		*slide=0;
		*safe_delay=(int32_t)ctl->jitt_comp_ts;
	}
	return ;
}


/**
 *rtp_session_set_jitter_compensation:
 *@session: a RtpSession
 *@milisec: the time interval in milisec to be jitter compensed.
 *
 * Sets the time interval for which packet are buffered instead of being delivered to the 
 * application.
 **/
void
rtp_session_set_jitter_compensation (RtpSession * session, int milisec)
{
	PayloadType *payload=NULL;
	if (session->rcv.pt!=-1) {
		payload = rtp_profile_get_payload (session->rcv.profile,session->rcv.pt);
	}/*else not set yet */
	jitter_control_init(&session->rtp.jittctl,milisec,payload);
}

void rtp_session_enable_adaptive_jitter_compensation(RtpSession *session, bool_t val){
	jitter_control_enable_adaptive(&session->rtp.jittctl,val);
}

bool_t rtp_session_adaptive_jitter_compensation_enabled(RtpSession *session){
	return session->rtp.jittctl.adaptive;
}
