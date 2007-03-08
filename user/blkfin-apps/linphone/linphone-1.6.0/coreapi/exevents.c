/*
linphone
Copyright (C) 2000  Simon MORLAT (simon.morlat@free.fr)

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

#include "exevents.h"
#include "linphonecore.h"
#include "private.h"
#include "mediastreamer2/mediastream.h"
#include <eXosip.h>
#include <osipparser2/osip_message.h>


extern void linphone_register_authentication_required(LinphoneCore *lc,eXosip_event_t *ev);
extern void linphone_invite_authentication_required(LinphoneCore* lc,LinphoneCall *lcall);
extern void linphone_subscription_new(LinphoneCore *lc,int did, int sid, char *from, char* contact);
extern void linphone_notify_recv(LinphoneCore *lc,char *from,int ss_status);
extern LinphoneProxyConfig *linphone_core_get_proxy_config_from_rid(LinphoneCore *lc, int rid);
void linphone_subscription_answered(LinphoneCore *lc,char *from, int sid);
void linphone_subscription_closed(LinphoneCore *lc,char *from, int did);




int linphone_call_accepted(LinphoneCore *lc,int id, const char *sdpbody)
{
	StreamParams *audio_params;
	LinphoneCall *call=lc->call;
	if (call==NULL){
		ms_warning("No call to accept.");
		return 0;
	}
	audio_params=&call->audio_params;
	call->auth_pending=FALSE;
	if (strlen(sdpbody)==0) {
		ms_warning("No sdp body in 200ok.");
		return 0;
	}
	if (call->state==LCStateAVRunning){
		return 0; /*already accepted*/
	}
	sdp_context_read_answer(lc->call->sdpctx,sdpbody);
	lc->vtable.show(lc);
	lc->vtable.display_status(lc,_("Connected."));
	lc->call->state=LCStateAVRunning;
	if (lc->ringstream!=NULL){
		ring_stop(lc->ringstream);
		lc->ringstream=NULL;
	}
	linphone_core_start_media_streams(lc,call);
	
	return 0;
}


int linphone_call_terminated(LinphoneCore *lc, eXosip_event_t *ev)
{
	/*stop ringing if necessary*/
	if (lc->call!=NULL){
		if (lc->call->cid!=ev->cid){
			/* this is not current call */
			ms_message("call %i terminated, this was not current call.",ev->cid);
			return 0;
		}
	}
	
	ms_message("Current call terminated...");
	if (lc->ringstream!=NULL) {
		ring_stop(lc->ringstream);
		lc->ringstream=NULL;
	}
	linphone_core_stop_media_streams(lc);
	lc->vtable.show(lc);
	lc->vtable.display_status(lc,_("Call terminated."));
	if (lc->vtable.bye_recv!=NULL)
		lc->vtable.bye_recv(lc,ev->remote_uri);
	if (lc->call!=NULL){
		linphone_call_destroy(lc->call);
		lc->call=NULL;
	}
	return 0;
}


int linphone_call_released(LinphoneCore *lc, int cid){
	LinphoneCall *call=lc->call;
	if (call!=NULL && call->cid==cid){
		
		linphone_call_destroy(lc->call);
		lc->call=NULL;
		lc->vtable.display_status(lc,_("Could not reach destination."));
	}
	return 0;
}

int linphone_call_failure(LinphoneCore *lc,int cid, int code)
{
	const char *reason;
	char *msg486=_("User is busy.");
	char *msg480=_("User is temporarily unavailable.");
	char *msg487=_("Request Cancelled.");
	/*char *retrymsg=_("%s. Retry after %i minute(s).");*/
	char *msg600=_("User does not want to be disturbed.");
	char *msg603=_("Call declined.");
	char* tmpmsg=msg486;

	
	lc->vtable.show(lc);
	
	switch(code)
	{
		case 401:
		case 407:
			if (lc->call!=NULL) linphone_invite_authentication_required(lc,lc->call);
			return 0;
			break;
		case 400:
			lc->vtable.display_status(lc,_("Bad request"));
		break;
		case 404:
			lc->vtable.display_status(lc,_("User cannot be found at given address."));
		break;
		case 415:
			lc->vtable.display_status(lc,_("Remote user cannot support any of proposed codecs."));
		break;
		case 480:
			tmpmsg=msg480;
		case 486:
			/*
			msg_header_getbyname(msg,"retry-after",0,&retry);
			if (retry!=NULL)
			{
				umsg=g_malloc(strlen(tmpmsg)+strlen(retrymsg)+13);
				sprintf(umsg,retrymsg,tmpmsg,atoi(retry->hvalue)/60);
				lc->vtable.display_message(lc,umsg);
				ms_free(umsg);
			}*/		
			lc->vtable.display_message(lc,tmpmsg);
		break;
		case 487:
			lc->vtable.display_status(lc,msg487);
		break;	
		case 600:
			lc->vtable.display_message(lc,msg600);
		break;
		case 603:
			lc->vtable.display_status(lc,msg603);
		break;
		case -110:  /* time out, call leg is lost */
			lc->vtable.display_status(lc,_("Timeout."));
		break;
		case -111:
			lc->vtable.display_status(lc,_("Remote host was found but refused connection."));
		break;
		
		default:
			if (code>0)
			{
				reason=osip_message_get_reason(code);
				lc->vtable.display_status(lc,(char*)reason);
			}
			else ms_warning("failure_cb unknown code=%i\n",code);	
	}
	if (lc->ringstream!=NULL) {
		ring_stop(lc->ringstream);
		lc->ringstream=NULL;
	}
	linphone_core_stop_media_streams(lc);
	if (lc->call!=NULL) linphone_call_destroy(lc->call);
	lc->call=NULL;
	return 0;
}

extern sdp_handler_t linphone_sdphandler;

int linphone_inc_new_call(LinphoneCore *lc, eXosip_event_t *ev)
{
	char *barmesg,*answer;
	int status=200;
	sdp_context_t *ctx=NULL;
	osip_from_t *from_url=NULL;
	int cid=ev->cid;
	int did=ev->did;
	char *from=ev->remote_uri;
	char *sdp_body=ev->sdp_body;
#ifdef VINCENT_MAURY_RSVP
	char *textinfo=ev->textinfo;
 #endif
	
	osip_from_init(&from_url);
	osip_from_parse(from_url,from);
	
	/* first check if we can answer successfully to this invite */
	if (lc->presence_mode!=LINPHONE_STATUS_ONLINE){
		ms_message("Not present !! presence mode : %d\n",lc->presence_mode);
		eXosip_lock();
		if (lc->presence_mode==LINPHONE_STATUS_BUSY)
		  
		  eXosip_answer_call(did,486,NULL);
		else if (lc->presence_mode==LINPHONE_STATUS_AWAY
			 ||lc->presence_mode==LINPHONE_STATUS_BERIGHTBACK
			 ||lc->presence_mode==LINPHONE_STATUS_ONTHEPHONE
			 ||lc->presence_mode==LINPHONE_STATUS_OUTTOLUNCH
			 ||lc->presence_mode==LINPHONE_STATUS_OFFLINE)
		  eXosip_answer_call(did,480,NULL);
		else if (lc->presence_mode==LINPHONE_STATUS_NOT_DISTURB)
		  eXosip_answer_call(did,480,NULL);
		else if (lc->alt_contact!=NULL && lc->presence_mode==LINPHONE_STATUS_MOVED)
		  {
		    eXosip_set_redirection_address (did, lc->alt_contact);
		    eXosip_answer_call(did,302,NULL);
		    eXosip_set_redirection_address (did, NULL);
		  }
		else if (lc->alt_contact!=NULL && lc->presence_mode==LINPHONE_STATUS_ALT_SERVICE)
		  {
		    eXosip_set_redirection_address (did, lc->alt_contact);
		    eXosip_answer_call(did,380,NULL);
		    eXosip_set_redirection_address (did, NULL);
		  }
		else
		  eXosip_answer_call(did,486,NULL);
		eXosip_unlock();
		goto end;
	}
	/* not busy */
#ifdef VINCENT_MAURY_RSVP
	/* in qos mode, call already exists at the end of resource reservation */
	if (lc->call!=NULL && lc->rsvp_enable && strcmp(textinfo,"New Call")!=0){
#else
	if (lc->call!=NULL){
#endif
		eXosip_lock();
		eXosip_answer_call(did,486,NULL);
		eXosip_unlock();
		goto end;
	}
	if (strlen(sdp_body)==0){
		ms_warning("No sdp body !");
		eXosip_lock();
		eXosip_answer_call(did,603,NULL);
		eXosip_unlock();
		goto end;
	}
#ifdef VINCENT_MAURY_RSVP
	/* make the negotiation only once at the first invite received */
	if (strcmp(textinfo,"New Call")!=0)
	{
		
		lc->call=linphone_call_new_incoming(lc,from,ev->local_uri,cid,did);
		ctx=lc->call->sdpctx;
		/* get the result of the negociation */
		answer=sdp_context_get_answer(ctx,sdp_body);
		status=sdp_context_get_status(ctx);
	}
#else
	lc->call=linphone_call_new_incoming(lc,from,ev->local_uri,cid,did);
	ctx=lc->call->sdpctx;
	eXosip_set_sdp_port(did, lc->rtp_conf.audio_rtp_port);
	/* get the result of the negociation */
	answer=sdp_context_get_answer(ctx,sdp_body);
	status=sdp_context_get_status(ctx);

#endif
	switch(status)
	{
		case 200:
			/* vérification de la qos */
#ifdef VINCENT_MAURY_RSVP
			if (strcmp(textinfo,"With QoS")==0 && !lc->rsvp_enable)
				/* caller has QoS, we don't */
				lc->vtable.display_yes_no(lc,strdup(textinfo));
			else if (strcmp(textinfo,"Without QoS")==0 && lc->rsvp_enable)
				/* caller doesn't have QoS, we do ! */
				lc->vtable.display_yes_no(lc,strdup(textinfo));
			else if (strcmp(textinfo,"With QoS")==0 && lc->rsvp_enable)
			{
				/* we agree on With QoS */
				eXosip_lock();
				eXosip_answer_call_with_body(did,183,"application/sdp",answer);
				eXosip_unlock();
			}
			else if (strcmp(textinfo,"Without QoS")==0 && !lc->rsvp_enable ||
					strcmp(textinfo,"New Call")==0)
			{
				/* we agree on Without QoS */
				eXosip_lock();
				eXosip_answer_call(did,180,NULL);
				eXosip_unlock();
				/* play the ring */
				lc->ringstream=ring_start(lc->sound_conf.local_ring,
							2000,lc->sound_conf.ring_sndcard);
			}
#else
			eXosip_lock();
			eXosip_answer_call(did,180,NULL);
			eXosip_unlock();
			/* play the ring */
			if (lc->sound_conf.ring_sndcard!=NULL){
				ms_message("Starting local ring...");
				lc->ringstream=ring_start(lc->sound_conf.local_ring,2000,lc->sound_conf.ring_sndcard);
			}
#endif
			linphone_call_set_state(lc->call,LCStateRinging);
			{
				char *tmp;
				if (from_2char_without_params(from_url,&tmp)==0){
					barmesg=ortp_strdup_printf("%s %s",tmp,_("is contacting you."));
					lc->vtable.show(lc);
					lc->vtable.display_status(lc,barmesg);
					lc->vtable.inv_recv(lc,tmp);
					ms_free(barmesg);
					osip_free(tmp);
				}
			}
		break;
		default:	
			if (status==-1) status=415;
			ms_warning("Error during sdp negociation. status : %d\n",status);
			eXosip_lock();
			eXosip_answer_call(did,status,NULL);
			eXosip_unlock();
			linphone_call_destroy(lc->call);
			lc->call=NULL;
	}
	end:
		osip_from_free(from_url);
	return 0;
}

void linphone_do_automatic_redirect(LinphoneCore *lc, const char *contact){
	char *msg=ortp_strdup_printf(_("Redirected to %s..."),contact);
	lc->vtable.display_status(lc,msg);
	ms_free(msg);
	if (lc->call!=NULL) linphone_call_destroy(lc->call);
	lc->call=NULL;
	linphone_core_invite(lc,contact);
}

void linphone_call_redirected(LinphoneCore *lc, int cid,int code, const char *contact){
	switch(code){
		case 380:
			lc->vtable.display_url(lc,_("User is not reachable at the moment but he invites you\nto contact him using the following alternate resource:"),(char*)contact);
			if (lc->call!=NULL) linphone_call_destroy(lc->call);
			lc->call=NULL;
			break;
		case 302:
			linphone_do_automatic_redirect(lc,contact);
			break;
	}
}


/* these are the SdpHandler callbacks: we are called in to be aware of the content
of the SDP messages exchanged */

int linphone_set_audio_offer(sdp_context_t *ctx)
{
	LinphoneCall *call=(LinphoneCall*)sdp_context_get_user_pointer(ctx);
	LinphoneCore *lc=call->core;
	PayloadType *codec;
	MSList *elem;
	sdp_payload_t payload;
	
	
	elem=lc->codecs_conf.audio_codecs;
	while(elem!=NULL){
		codec=(PayloadType*) elem->data;
		if (linphone_core_check_payload_type_usability(lc,codec) && payload_type_enabled(codec)){
			sdp_payload_init(&payload);
			payload.a_rtpmap=ortp_strdup_printf("%s/%i/1",codec->mime_type,codec->clock_rate);
			payload.pt=rtp_profile_get_payload_number_from_rtpmap(lc->local_profile,payload.a_rtpmap);
			payload.localport=lc->rtp_conf.audio_rtp_port;
			if (strcasecmp(codec->mime_type,"iLBC")==0){
				/* prefer the 30 ms mode */
				payload.a_fmtp="ptime=30";
			}
			sdp_context_add_audio_payload(ctx,&payload);
			ms_free(payload.a_rtpmap);
		}
		elem=ms_list_next(elem);
	}
	/* add telephone-event payload*/
	sdp_payload_init(&payload);
	payload.pt=rtp_profile_get_payload_number_from_mime(lc->local_profile,"telephone-event");
	payload.a_rtpmap="telephone-event/8000";
	payload.a_fmtp="0-11";
	if (lc->dw_audio_bw>0) payload.b_as_bandwidth=lc->dw_audio_bw;
	sdp_context_add_audio_payload(ctx,&payload);
	return 0;
}


int linphone_set_video_offer(sdp_context_t *ctx)
{
	LinphoneCall *call=(LinphoneCall*)sdp_context_get_user_pointer(ctx);
	LinphoneCore *lc=call->core;
	PayloadType *codec;
	MSList *elem;
	bool_t firsttime=TRUE;	

	if (!linphone_core_video_enabled(lc)) return -1;

	for(elem=lc->codecs_conf.video_codecs;elem!=NULL;elem=ms_list_next(elem)){
		codec=(PayloadType*) elem->data;
		if (linphone_core_check_payload_type_usability(lc,codec) && payload_type_enabled(codec)){
			sdp_payload_t payload;
			sdp_payload_init(&payload);
			payload.line=1;
			payload.a_rtpmap=ortp_strdup_printf("%s/%i",codec->mime_type,codec->clock_rate);
			payload.localport=lc->rtp_conf.video_rtp_port;
			payload.pt=rtp_profile_get_payload_number_from_rtpmap(lc->local_profile,payload.a_rtpmap);
			payload.a_fmtp=codec->recv_fmtp;
			if(firsttime){
				firsttime=FALSE;
				if (lc->dw_video_bw>0)
					payload.b_as_bandwidth=lc->dw_video_bw;
			}
			sdp_context_add_video_payload(ctx,&payload);
			ms_free(payload.a_rtpmap);
		}
	}
	return 0;
}

typedef enum {
	Unsupported,
	Supported,
	SupportedAndValid  /* valid= the presence of this codec is enough to make a call */
}SupportLevel;

SupportLevel linphone_payload_is_supported(LinphoneCore *lc, sdp_payload_t *payload,RtpProfile *local_profile,RtpProfile *dialog_profile, bool_t answering)
{
	int localpt;
	SupportLevel ret;
	if (payload->a_rtpmap!=NULL){
		localpt=rtp_profile_get_payload_number_from_rtpmap(local_profile,payload->a_rtpmap);
	}else{
		localpt=payload->pt;
		ms_warning("payload has no rtpmap.");
	}
	
	if (localpt>=0 && localpt <128 ){
		/* this payload is understood, but does the user want to use it ?? */
		PayloadType *rtppayload;
		rtppayload=rtp_profile_get_payload(local_profile,localpt);
		if (rtppayload==NULL) {
			ms_warning("strange error !!");
			return Unsupported;
		}
		if (strcmp(rtppayload->mime_type,"telephone-event")!=0){
			if (answering && !linphone_core_check_payload_type_usability(lc,rtppayload) ){
				ms_warning("payload %s is not usable",rtppayload->mime_type);
				return Unsupported;
			}
			if ( !payload_type_enabled(rtppayload)) {
				ms_warning("payload %s is not enabled.",rtppayload->mime_type);
				return Unsupported;
			}
			ret=SupportedAndValid;
		}else ret=Supported;
		if (dialog_profile!=NULL){
			int dbw,ubw;
			/* this payload is supported in our local rtp profile, so add it to the dialog rtp
			profile */
			rtppayload=payload_type_clone(rtppayload);
			rtp_profile_set_payload(dialog_profile,payload->pt,rtppayload);
			/* add to the rtp payload type some other parameters (bandwidth) */
			if (rtppayload->type==PAYLOAD_VIDEO){
				dbw=lc->dw_video_bw;
				ubw=lc->up_video_bw;
			}else{ 
				dbw=lc->dw_audio_bw;
				ubw=lc->up_audio_bw;
			}
			if (payload->b_as_bandwidth!=0){
				/*obey to remote bandwidth constraint AND our own upbandwidth constraint*/
				rtppayload->normal_bitrate=1000*get_min_bandwidth(
					payload->b_as_bandwidth,
					ubw);
			}
			/* but anyway give our download bandwidth constraint*/
			payload->b_as_bandwidth=(dbw>0) ? dbw : 0;
			if (payload->a_fmtp!=NULL){
				payload_type_set_send_fmtp(rtppayload,payload->a_fmtp);
			}
			payload->a_fmtp=rtppayload->recv_fmtp;
		}
		return ret;
	}
	return Unsupported;
}

int linphone_accept_audio_offer(sdp_context_t *ctx,sdp_payload_t *payload)
{
	RtpProfile *remote_profile;
	StreamParams *params;
	SupportLevel supported;
	LinphoneCall *call=(LinphoneCall*)sdp_context_get_user_pointer(ctx);
	LinphoneCore *lc=call->core;
	
	if (call->profile==NULL){
		/* create a remote user agent profile */
		call->profile=remote_profile=rtp_profile_new("remote");
	}
	remote_profile=call->profile;
	/* see if this codec is supported in our local rtp profile*/
	supported=linphone_payload_is_supported(lc,payload,lc->local_profile,remote_profile,TRUE);
	if (supported==Unsupported) {
		ms_message("Refusing audio codec %i (%s)",payload->pt,payload->a_rtpmap);
		return -1;
	}
	if (supported==SupportedAndValid) {
		params=&call->audio_params;
		if (params->initialized==0){
			/* this is the first codec we may accept*/
			params->localport=payload->localport=lc->rtp_conf.audio_rtp_port;
			params->remoteport=payload->remoteport;
			params->line=payload->line;
			params->pt=payload->pt; /* remember the first payload accepted */
			params->remoteaddr=payload->c_addr;
			params->initialized=1;
		}else{
			/* refuse all other audio lines*/
			if(params->line!=payload->line) return -1;
		}
	}
	return 0;
}

int linphone_accept_video_offer(sdp_context_t *ctx,sdp_payload_t *payload)
{
	LinphoneCall *call=(LinphoneCall*)sdp_context_get_user_pointer(ctx);
	LinphoneCore *lc=call->core;
	RtpProfile *remote_profile;
	StreamParams *params;
	SupportLevel supported;

	if (!linphone_core_video_enabled(lc)) return -1;

	if (call->profile==NULL){
		/* create a remote user agent profile */
		call->profile=rtp_profile_new("remote");
	}
	remote_profile=call->profile;
	/* see if this codec is supported in our local rtp profile*/
	supported=linphone_payload_is_supported(lc,payload,lc->local_profile,remote_profile,TRUE);
	if (supported==Unsupported) {
		ms_message("Refusing video codec %i (%s)",payload->pt,payload->a_rtpmap);
		return -1;
	}
	if (supported==SupportedAndValid){
		params=&call->video_params;
		if (params->initialized==0){
			/* this is the first codec we may accept*/
			params->localport=payload->localport=lc->rtp_conf.video_rtp_port;
			params->remoteport=payload->remoteport;
			params->line=payload->line;
			params->pt=payload->pt; /* remember the first payload accepted */
			params->remoteaddr=payload->c_addr;
			params->initialized=1;
		}else{
			/* refuse all other video lines*/
			if(params->line!=payload->line) return -1;
		}
	}
	return 0;
}

int linphone_read_audio_answer(sdp_context_t *ctx,sdp_payload_t *payload)
{
	LinphoneCall *call=(LinphoneCall*)sdp_context_get_user_pointer(ctx);
	LinphoneCore *lc=call->core;
	StreamParams *params;
	SupportLevel supported;
	
	/* paranoid check: see if this codec is supported in our local rtp profile*/
	supported=linphone_payload_is_supported(lc, payload,lc->local_profile,call->profile,FALSE);
	if (supported==Unsupported) {
		ms_warning("This remote sip phone did not answer properly to my sdp offer!");
		return 0;
	}
	if (supported==SupportedAndValid){
		params=&call->audio_params;
		if (params->initialized==0){
			/* this is the first codec we may accept*/
			params->localport=lc->rtp_conf.audio_rtp_port;
			params->remoteport=payload->remoteport;
			params->line=payload->line;
			params->pt=payload->pt; /* remember the first payload accepted */
			params->remoteaddr=payload->c_addr;
			params->initialized=1;
		}
	}
	return 0;
}

int linphone_read_video_answer(sdp_context_t *ctx,sdp_payload_t *payload)
{
	LinphoneCall *call=(LinphoneCall*)sdp_context_get_user_pointer(ctx);
	LinphoneCore *lc=call->core;
	StreamParams *params;
	SupportLevel supported;
	
	/* paranoid check: see if this codec is supported in our local rtp profile*/
	supported=linphone_payload_is_supported(lc, payload,lc->local_profile,call->profile,FALSE);
	if (supported==Unsupported) {
		ms_warning("This remote sip phone did not answer properly to my sdp offer!");
		return 0;
	}
	if (supported==SupportedAndValid){
		params=&call->video_params;
		if (params->initialized==0){
			/* this is the first codec we may accept*/
			params->localport=lc->rtp_conf.video_rtp_port;
			params->remoteport=payload->remoteport;
			params->line=payload->line;
			params->pt=payload->pt; /* remember the first payload accepted */
			params->remoteaddr=payload->c_addr;
			params->initialized=1;
		}
	}
	return 0;
}

void linphone_call_proceeding(LinphoneCore *lc, int cid, int did){
	if (lc->call==NULL){
		ms_warning("Bug in call_proceeding()");
		return;
	}
	lc->call->cid=cid;
	lc->call->did=did;
	eXosip_set_sdp_port(did, lc->rtp_conf.audio_rtp_port);
}

void linphone_call_ringing(LinphoneCore *lc, eXosip_event_t *ev){
	
	if (lc->audiostream!=NULL) return; /*already listening to remote host */
	linphone_call_proceeding(lc,ev->cid,ev->did);
	
	if (ev->status_code==180){
		if (lc->ringstream!=NULL) return;	/*already ringing !*/
		if (lc->sound_conf.play_sndcard!=NULL){
			ms_message("Remote ringing...");
			lc->ringstream=ring_start(lc->sound_conf.remote_ring,2000,lc->sound_conf.play_sndcard);
		}
	}else if (strlen(ev->sdp_body)>0){
		/* somebody reported a server who uses a 183 answer to establish mediastreams and play
		an informationnal message */
		linphone_call_accepted(lc,ev->did,ev->sdp_body);
	}
	
}


void linphone_registration_faillure(LinphoneCore *lc,eXosip_event_t *ev)
{
	char *msg;
	switch(ev->status_code){
		case 401:
		case 407:
			linphone_register_authentication_required(lc,ev);
			break;
		default:
			if (strlen(ev->reason_phrase)==0) msg=ortp_strdup_printf(_("Registration on %s failed (timeout)."),ev->req_uri);
			else msg=ev->reason_phrase;
			lc->vtable.display_status(lc,msg);
			if ( msg != ev->reason_phrase ) ms_free(msg);
	}
	
}

void linphone_registration_success(LinphoneCore *lc,eXosip_event_t *ev){
	LinphoneProxyConfig *cfg;
	char *msg=ms_strdup_printf(_("Registration on %s sucessful."),ev->req_uri);
	lc->vtable.display_status(lc,msg);
	ms_free(msg);
	cfg=linphone_core_get_proxy_config_from_rid(lc,ev->rid);
	ms_return_if_fail(cfg!=NULL);
	cfg->auth_pending=FALSE;
	cfg->registered=TRUE;
}

void linphone_core_process_event(LinphoneCore *lc,eXosip_event_t *ev)
{
	switch(ev->type){
		case EXOSIP_CALL_ANSWERED:
			ms_message("CALL_ANSWERED\n");
			linphone_call_accepted(lc,ev->did,ev->sdp_body);
			/*send the ack once streams are started*/
			eXosip_send_ack(ev->did);
			break;
		case EXOSIP_CALL_CLOSED:
		case EXOSIP_CALL_CANCELLED:
			ms_message("CALL_CLOSED or CANCELLED\n");
			linphone_call_terminated(lc,ev);
			break;
		case EXOSIP_CALL_TIMEOUT:
		case EXOSIP_CALL_NOANSWER:
			ms_message("CALL_TIMEOUT or NOANSWER\n");
			linphone_call_failure(lc,ev->did,-110);
			break;
		case EXOSIP_CALL_REQUESTFAILURE:
		case EXOSIP_CALL_GLOBALFAILURE:
		case EXOSIP_CALL_SERVERFAILURE:
			ms_message("CALL_REQUESTFAILURE or GLOBALFAILURE or SERVERFAILURE\n");
			linphone_call_failure(lc,ev->did,ev->status_code);
			break;
		case EXOSIP_CALL_NEW:
			ms_message("CALL_NEW\n");
			/* CALL_NEW is used twice in qos mode : 
			 * when you receive invite (textinfo = "With QoS" or "Without QoS")
			 * and when you receive update (textinfo = "New Call") */
			linphone_inc_new_call(lc,ev);
			break;
		case EXOSIP_CALL_ACK:
			ms_message("CALL_ACK\n");
			break;
		case EXOSIP_CALL_REDIRECTED:
			ms_message("CALL_REDIRECTED\n");
			linphone_call_redirected(lc,ev->did,ev->status_code,ev->remote_contact);
			break;
		case EXOSIP_CALL_PROCEEDING:
			ms_message("CALL_PROCEEDING\n");
			linphone_call_proceeding(lc,ev->cid,ev->did);
			break;
		case EXOSIP_CALL_RINGING:
			ms_message("CALL_RINGING\n");
			linphone_call_ringing(lc,ev);
			break;
		case EXOSIP_IN_SUBSCRIPTION_NEW:
			ms_message("CALL_SUBSCRIPTION_NEW or UPDATE\n");
			linphone_subscription_new(lc,ev->did,ev->nid,ev->remote_uri,ev->remote_contact);
			break;
		case EXOSIP_SUBSCRIPTION_NOTIFY:
			ms_message("CALL_SUBSCRIPTION_NOTIFY\n");
			linphone_notify_recv(lc,ev->remote_uri,ev->online_status);
			break;
		case EXOSIP_SUBSCRIPTION_ANSWERED:
			linphone_subscription_answered(lc,ev->remote_uri, ev->did);
			break;
		case EXOSIP_SUBSCRIPTION_CLOSED:
			linphone_subscription_closed(lc,ev->remote_uri,ev->did);
			break;
		case EXOSIP_CALL_HOLD:
		case EXOSIP_CALL_OFFHOLD:
			ms_message("CALL_HOLD ou OFFHOLD\n");
			break;
		case EXOSIP_CALL_STARTAUDIO:
			ms_message("CALL_STARTAUDIO\n");
			break;
		case EXOSIP_CALL_RELEASED:
			ms_message("CALL_RELEASED\n");
			linphone_call_released(lc, ev->cid);
			break;
		case EXOSIP_REGISTRATION_FAILURE:
			ms_message("REGISTRATION_FAILURE\n");
			linphone_registration_faillure(lc,ev);
			break;
		case EXOSIP_REGISTRATION_SUCCESS:
			linphone_registration_success(lc,ev);
			break;
		case EXOSIP_MESSAGE_NEW:
			linphone_core_text_received(lc,ev->remote_uri,ev->sdp_body);
		default:
			break;
	}
	eXosip_event_free(ev);
}
