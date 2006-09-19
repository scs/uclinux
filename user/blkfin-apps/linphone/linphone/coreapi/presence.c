/*
linphone
Copyright (C) 2000  Simon MORLAT (simon.morlat@linphone.org)

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

#include "linphonecore.h"
#include <eXosip.h>
#include <osipparser2/osip_message.h>
#include "private.h"

extern int linphone_friend_set_contact(LinphoneFriend *lf, const char *contact);
extern MSList *find_friend(MSList *fl, const char *friend, LinphoneFriend **lf);
extern const char *__policy_enum_to_str(LinphoneSubscribePolicy pol);

int linphone_online_status_to_eXosip(LinphoneOnlineStatus os){
	static int convtable[LINPHONE_STATUS_END];
	static bool_t initialized=FALSE;
	if (!initialized){
		convtable[LINPHONE_STATUS_AWAY]=EXOSIP_NOTIFY_AWAY;
		convtable[LINPHONE_STATUS_UNKNOWN]=EXOSIP_NOTIFY_UNKNOWN;
		convtable[LINPHONE_STATUS_ONLINE]=EXOSIP_NOTIFY_ONLINE;
		convtable[LINPHONE_STATUS_BUSY]=EXOSIP_NOTIFY_BUSY;

		/* added by amd */
		convtable[LINPHONE_STATUS_BERIGHTBACK]=EXOSIP_NOTIFY_BERIGHTBACK;
		convtable[LINPHONE_STATUS_ONTHEPHONE]=EXOSIP_NOTIFY_ONTHEPHONE;
		convtable[LINPHONE_STATUS_OUTTOLUNCH]=EXOSIP_NOTIFY_OUTTOLUNCH;
		convtable[LINPHONE_STATUS_NOT_DISTURB]=EXOSIP_NOTIFY_BUSY;
		convtable[LINPHONE_STATUS_MOVED]=EXOSIP_NOTIFY_AWAY;
		convtable[LINPHONE_STATUS_ALT_SERVICE]=EXOSIP_NOTIFY_AWAY;

		convtable[LINPHONE_STATUS_OFFLINE]=EXOSIP_NOTIFY_CLOSED;

		initialized=TRUE;
	}
	return convtable[os];
}


void linphone_core_add_subscriber(LinphoneCore *lc, const char *subscriber, const char *contact, int did){
	LinphoneFriend *fl=linphone_friend_new_with_addr(subscriber);
	if (fl==NULL) return ;
	linphone_friend_set_nid(fl,did);
	linphone_friend_set_contact(fl,contact);
	linphone_friend_set_inc_subscribe_policy(fl,LinphoneSPAccept);
	fl->inc_subscribe_pending=TRUE;
	lc->subscribers=ms_list_append(lc->subscribers,(void *)fl);
	if (lc->vtable.new_unknown_subscriber!=NULL) {
		char *clean_subscriber;	/* we need to remove tags...*/
		from_2char_without_params(fl->url,&clean_subscriber);
		lc->vtable.new_unknown_subscriber(lc,fl,clean_subscriber);
		ms_free(clean_subscriber);
	}
}

void linphone_core_reject_subscriber(LinphoneCore *lc, LinphoneFriend *lf){
	linphone_friend_set_inc_subscribe_policy(lf,LinphoneSPDeny);
	eXosip_lock();
	eXosip_notify_accept_subscribe(lf->nid,200,EXOSIP_SUBCRSTATE_TERMINATED,EXOSIP_NOTIFY_CLOSED);
	eXosip_unlock();
}

static void __do_notify(void * data, void * user_data){
	int *tab=(int*)user_data;
	LinphoneFriend *lf=(LinphoneFriend*)data;
	linphone_friend_notify(lf,tab[0],tab[1]);
}

void __linphone_core_notify_all_friends(LinphoneCore *lc, int ss, int os){
	int tab[2];
	tab[0]=ss;
	tab[1]=os;
	ms_list_for_each2(lc->friends,__do_notify,(void *)tab);
}

void linphone_core_notify_all_friends(LinphoneCore *lc, LinphoneOnlineStatus os){
	int ss=linphone_online_status_to_eXosip(os);
	ms_message("Notifying all friends that we are in status %i/%i",os,ss);
	__linphone_core_notify_all_friends(lc,EXOSIP_SUBCRSTATE_ACTIVE,ss);
}

/* check presence state before answering to call; returns TRUE if we can proceed, else answer the appropriate answer
to close the dialog*/
bool_t linphone_core_check_presence(LinphoneCore *lc){
	return TRUE;
}

void linphone_subscription_new(LinphoneCore *lc, int did,int sid, char *from, char *contact){
	LinphoneFriend *lf=NULL;
	
	ms_message("Receiving new subscription from %s.",from);
	/* check if we answer to this subscription */
	if (find_friend(lc->friends,from,&lf)!=NULL){
		linphone_friend_set_nid(lf,did);
		linphone_friend_done(lf);	/*this will do all necessary actions */
	}else{
		/* check if this subscriber is in our black list */
		if (find_friend(lc->subscribers,from,&lf)){
			if (lf->pol==LinphoneSPDeny){
				ms_message("Rejecting %s because we already rejected it once.",from);
				linphone_core_reject_subscriber(lc,lf);
			}
			else {
				/* else it is in wait for approval state, because otherwise it is in the friend list.*/
				ms_message("New subscriber found in friend list, in %s state.",__policy_enum_to_str(lf->pol));
			}
		}else linphone_core_add_subscriber(lc,from,contact,did);
	}
}

void linphone_notify_recv(LinphoneCore *lc,char *from,int online_status)
{
	char *status;
	char *img;
	char *tmp;
	LinphoneFriend *lf;
	osip_from_t *friend=NULL;
	switch (online_status){
		case EXOSIP_NOTIFY_PENDING:
			status=_("Waiting for Approval");
			img="linphone/sip-wfa.png";
			break;
		case EXOSIP_NOTIFY_ONLINE:
			status=_("Online");
			img="linphone/sip-online.png";
			break;
		case EXOSIP_NOTIFY_BUSY:
			status=_("Busy");
			img="linphone/sip-busy.png";
			break;
		case EXOSIP_NOTIFY_BERIGHTBACK:
			status=_("Be Right Back");
			img="linphone/sip-bifm.png";
			break;
		case EXOSIP_NOTIFY_AWAY:
			status=_("Away");
			img="linphone/sip-away.png";
			break;
		case EXOSIP_NOTIFY_ONTHEPHONE:
			status=_("On The Phone");
			img="linphone/sip-otp.png";
			break;
		case EXOSIP_NOTIFY_OUTTOLUNCH:
			status=_("Out To Lunch");
			img="linphone/sip-otl.png";
			break;
		case EXOSIP_NOTIFY_CLOSED:
			status=_("Closed");
			img="linphone/sip-away.png";
			break;
		case EXOSIP_NOTIFY_UNKNOWN:
			status=_("Gone");
			img="linphone/sip-closed.png";
			break;
		default:
			ms_warning("Notify status not understood (%i)",online_status);
			status="unavailable";
			img="sip-away.png";
			break;
	}
	/* find a friend in our list that matches the from (from may contain tags and other confusing things)*/
	find_friend(lc->friends,from,&lf);
	ms_message("We are notified that %s has online status %i",from,online_status);
	if (lf!=NULL){
		friend=lf->url;
		from_2char_without_params(friend,&tmp);
		lc->vtable.notify_recv(lc,(LinphoneFriend*)lf,tmp,status,img);
		ms_free(tmp);
		if (online_status==EXOSIP_NOTIFY_CLOSED 
			|| online_status==EXOSIP_NOTIFY_UNKNOWN) lf->sid=-1;
	}else{
		ms_message("But this person is not part of our friend list, so we don't care.");
	}
}

void linphone_subscription_answered(LinphoneCore *lc,char *from, int sid){
	LinphoneFriend *lf;
	find_friend(lc->friends,from,&lf);
	if (lf!=NULL){
		linphone_friend_set_sid(lf,sid);
	}else{
		ms_warning("Receiving answer for unknown subscribe to %s", from);
	}
}
void linphone_subscription_closed(LinphoneCore *lc,char *from, int did){
	LinphoneFriend *lf;
	find_friend(lc->friends,from,&lf);
	if (lf!=NULL){
		linphone_friend_set_sid(lf,-1);
	}else{
		ms_warning("Receiving close for unknown subscribe to %s", from);
	}
}
