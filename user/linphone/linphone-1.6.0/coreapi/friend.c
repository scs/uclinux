/***************************************************************************
 *            friend.c
 *
 *  Sat May 15 15:25:16 2004
 *  Copyright  2004  Simon Morlat
 *  Email
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "linphonecore.h"
#include "private.h"
#include <eXosip.h>
#include <osipparser2/osip_message.h>
#include "lpconfig.h"


static int friend_data_compare(const void * a, const void * b, void * data){
	osip_from_t *fa=((LinphoneFriend*)a)->url;
	osip_from_t *fb=((LinphoneFriend*)b)->url;
	char *ua,*ub;
	ua=fa->url->username;
	ub=fb->url->username;
	if (ua!=NULL && ub!=NULL) {
		//printf("Comparing usernames %s,%s\n",ua,ub);
		return strcasecmp(ua,ub);
	}
	else {
		/* compare hosts*/
		ua=fa->url->host;
		ub=fb->url->host;
		if (ua!=NULL && ub!=NULL){
			int ret=strcasecmp(ua,ub);
			//printf("Comparing hostnames %s,%s,res=%i\n",ua,ub,ret);
			return ret;
		}
		else return -1;
	}
}

static int friend_compare(const void * a, const void * b){
	return friend_data_compare(a,b,NULL);
}


MSList *find_friend(MSList *fl, const char *friend, LinphoneFriend **lf){
	osip_from_t *tmpf=NULL;
	int err;
	MSList *res=NULL;
	LinphoneFriend dummy;
	if (lf!=NULL) *lf=NULL;
	osip_from_init(&tmpf);
	err=osip_from_parse(tmpf,friend);
	if (err<0){
		ms_warning("Invalid friend to search sip uri: %s",friend);
		osip_from_free(tmpf);
		return NULL;
	}
	dummy.url=tmpf;
	res=ms_list_find_custom(fl,friend_compare,&dummy);
	osip_from_free(tmpf);
	if (lf!=NULL && res!=NULL) *lf=(LinphoneFriend*)res->data;
	return res;
}

void __linphone_friend_do_subscribe(LinphoneFriend *fr){
	int err;
	char *req_uri;
	char *friend=NULL;
	char *route=NULL;
	osip_from_to_str(fr->url,&friend);
	if (fr->proxy!=NULL){
		route=fr->proxy->reg_route;
	}
	if (fr->contact!=NULL) req_uri=fr->contact;
	else req_uri=friend;
	if (fr->sid<0){
		/* people for which we don't have yet an answer should appear as offline */
		fr->lc->vtable.notify_recv(fr->lc,(LinphoneFriend*)fr,friend,_("Gone"),"linphone/sip-closed.png");
	}
	eXosip_lock();
	err=-1;
	if (fr->sid>0)
	  err = eXosip_subscribe_refresh(fr->sid, "3600");
	else
	  fr->sid=-2;
	if (err<0)
	  {
	    err=eXosip_subscribe((char*)req_uri,(char*)linphone_core_get_primary_contact(fr->lc),route);
	  }
	eXosip_unlock();
	fr->last_outsubsc=time(NULL);
	if (err<0){
		ms_warning("Could not subscribe to %s.",friend);
	}
	osip_free(friend);
}


LinphoneFriend * linphone_friend_new(){
	LinphoneFriend *obj=ms_new0(LinphoneFriend,1);
	obj->nid=-1;
	obj->sid=-1;
	obj->pol=LinphoneSPAccept;
	obj->subscribe=TRUE;
	return obj;	
}

LinphoneFriend *linphone_friend_new_with_addr(const char *addr){
	LinphoneFriend *fr=linphone_friend_new();
	if (linphone_friend_set_sip_addr(fr,addr)<0){
		linphone_friend_destroy(fr);
		return NULL;
	}
	return fr;
}


int linphone_friend_set_sip_addr(LinphoneFriend *lf, const char *addr){
	int err;
	osip_from_t *fr=NULL;
	osip_from_init(&fr);
	err=osip_from_parse(fr,addr);
	if (err<0) {
		ms_warning("Invalid friend sip uri: %s",addr);
		osip_from_free(fr);
		return -1;
	}
	if (lf->url!=NULL) osip_from_free(lf->url);	
	lf->url=fr;
	return 0;
}

int linphone_friend_set_contact(LinphoneFriend *lf, const char *contact)
{
	if (lf->contact!=NULL) ms_free(lf->contact);
	if (contact!=NULL) lf->contact=ms_strdup(contact);
	else lf->contact=NULL;
	return 0;
}

int linphone_friend_send_subscribe(LinphoneFriend *fr, bool_t val){
	fr->subscribe=val;
	return 0;
}

int linphone_friend_set_inc_subscribe_policy(LinphoneFriend *fr, LinphoneSubscribePolicy pol)
{
	fr->pol=pol;
	return 0;
}

int linphone_friend_set_proxy(LinphoneFriend *fr, struct _LinphoneProxyConfig *cfg){
	fr->proxy=cfg;
	return 0;
}

void linphone_friend_set_sid(LinphoneFriend *lf, int cid){
	lf->sid=cid;
}
void linphone_friend_set_nid(LinphoneFriend *lf, int cid){
	lf->nid=cid;
	lf->inc_subscribe_pending=TRUE;
}

void linphone_friend_notify(LinphoneFriend *lf, int ss, int os){
	//printf("Wish to notify %p, lf->nid=%i\n",lf,lf->nid);
	if (lf->nid!=-1)
	  {
	    eXosip_lock();
	    eXosip_notify(lf->nid,ss,os);
	    eXosip_unlock();
	  }
}

void linphone_friend_destroy(LinphoneFriend *lf){
	eXosip_lock();
	if (lf->nid>=0) eXosip_notify(lf->nid,EXOSIP_SUBCRSTATE_TERMINATED,EXOSIP_NOTIFY_CLOSED);
	eXosip_unlock();
	eXosip_lock();
	if (lf->sid>=0) eXosip_subscribe_close(lf->sid);
	eXosip_unlock();
	if (lf->url!=NULL) osip_from_free(lf->url);
	ms_free(lf);
}

void linphone_friend_check_for_removed_proxy(LinphoneFriend *lf, LinphoneProxyConfig *cfg){
	if (lf->proxy==cfg){
		lf->proxy=NULL;
	}
}

char *linphone_friend_get_addr(LinphoneFriend *lf){
	char *ret,*tmp;
	if (lf->url==NULL) return NULL;
	osip_uri_to_str(lf->url->url,&tmp);
	ret=ms_strdup(tmp);
	osip_free(tmp);
	return ret;
}

char *linphone_friend_get_name(LinphoneFriend *lf){
	if (lf->url==NULL) return NULL;
	if (lf->url->displayname==NULL) return NULL;
	return ms_strdup(lf->url->displayname);
}

char * linphone_friend_get_url(LinphoneFriend *lf){
	char *tmp,*ret;
	if (lf->url==NULL) return NULL;
	osip_from_to_str(lf->url,&tmp);
	ret=ms_strdup(tmp);
	ms_free(tmp);
	return ret;
}



void linphone_friend_apply(LinphoneFriend *fr, LinphoneCore *lc){
	if (fr->url==NULL) {
		ms_warning("No sip url defined.");
		return;
	}
	fr->lc=lc;
	
	if (fr->inc_subscribe_pending){
		switch(fr->pol){
			case LinphoneSPWait:
				eXosip_lock();
				eXosip_notify_accept_subscribe(fr->nid,202,EXOSIP_SUBCRSTATE_PENDING,EXOSIP_NOTIFY_PENDING);
				eXosip_unlock();
				break;
			case LinphoneSPAccept:
				if (fr->lc!=NULL)
				  {
					eXosip_lock();
					eXosip_notify_accept_subscribe(fr->nid,200,EXOSIP_SUBCRSTATE_ACTIVE,linphone_online_status_to_eXosip(fr->lc->presence_mode));
					eXosip_unlock();
				  }
				break;
			case LinphoneSPDeny:
			
				break;
		}
		fr->inc_subscribe_pending=FALSE;
	}
	if (fr->subscribe && fr->sid==-1){
		
		__linphone_friend_do_subscribe(fr);
	}
	ms_message("linphone_friend_apply() done.");
}

void linphone_friend_edit(LinphoneFriend *fr){
}
void linphone_friend_done(LinphoneFriend *fr){
	ms_return_if_fail(fr!=NULL);
	if (fr->lc==NULL) return;
	linphone_friend_apply(fr,fr->lc);
}

void linphone_core_add_friend(LinphoneCore *lc, LinphoneFriend *lf)
{
	ms_return_if_fail(lf->lc==NULL);
	ms_return_if_fail(lf->url!=NULL);
	linphone_friend_apply(lf,lc);
	lc->friends=ms_list_insert_sorted(lc->friends,(void *)lf,friend_compare);
	return ;
}

void linphone_core_remove_friend(LinphoneCore *lc, LinphoneFriend* fl){
	MSList *el=ms_list_find(lc->friends,(void *)fl);
	if (el!=NULL){
		lc->friends=ms_list_remove_link(lc->friends,el);
		linphone_friend_destroy((LinphoneFriend*)el->data);
	}
}



void linphone_core_refresh_subscribes(LinphoneCore *lc){
	MSList *elem;
	int cur=time(NULL);
	for (elem=lc->friends;elem!=NULL;elem=ms_list_next(elem)){
		LinphoneFriend *lf=(LinphoneFriend*)elem->data;
		if (lf->subscribe && (cur-lf->last_outsubsc>500)) __linphone_friend_do_subscribe(lf);
		else if (lf->subscribe && (cur-lf->last_outsubsc>150)
			 && lf->sid<=0) __linphone_friend_do_subscribe(lf);
	}
}

#define key_compare(key, word) strncasecmp((key),(word),strlen(key))

LinphoneSubscribePolicy __policy_str_to_enum(const char* pol){
	if (key_compare("accept",pol)==0){
		return LinphoneSPAccept;
	}
	if (key_compare("deny",pol)==0){
		return LinphoneSPDeny;
	}
	if (key_compare("wait",pol)==0){
		return LinphoneSPWait;
	}
	ms_warning("Unrecognized subscribe policy: %s",pol);
	return LinphoneSPWait;
}

LinphoneProxyConfig *__index_to_proxy(LinphoneCore *lc, int index){
	if (index>=0) return (LinphoneProxyConfig*)ms_list_nth_data(lc->sip_conf.proxies,index);
	else return NULL;
}

LinphoneFriend * linphone_friend_new_from_config_file(LinphoneCore *lc, int index){
	const char *tmp;
	char item[50];
	int a;
	LinphoneFriend *lf;
	LpConfig *config=lc->config;
	
	sprintf(item,"friend_%i",index);
	
	if (!lp_config_has_section(config,item)){
		return NULL;
	}
	
	tmp=lp_config_get_string(config,item,"url",NULL);
	if (tmp==NULL) {
		return NULL;
	}
	lf=linphone_friend_new_with_addr(tmp);
	if (lf==NULL) {
		return NULL;
	}
	tmp=lp_config_get_string(config,item,"pol",NULL);
	if (tmp==NULL) linphone_friend_set_inc_subscribe_policy(lf,LinphoneSPWait);
	else{
		linphone_friend_set_inc_subscribe_policy(lf,__policy_str_to_enum(tmp));
	}
	a=lp_config_get_int(config,item,"subscribe",0);
	linphone_friend_send_subscribe(lf,a);
		
	a=lp_config_get_int(config,item,"proxy",-1);
	if (a!=-1) {
		linphone_friend_set_proxy(lf,__index_to_proxy(lc,a));
	}
	return lf;
}

const char *__policy_enum_to_str(LinphoneSubscribePolicy pol){
	switch(pol){
		case LinphoneSPAccept:
			return "accept";
			break;
		case LinphoneSPDeny:
			return "deny";
			break;
		case LinphoneSPWait:
			return "wait";
			break;
	}
	ms_warning("Invalid policy enum value.");
	return "wait";
}

void linphone_friend_write_to_config_file(LpConfig *config, LinphoneFriend *lf, int index){
	char key[50];
	char *tmp;
	int a;
	
	sprintf(key,"friend_%i",index);
	
	if (lf==NULL){
		lp_config_clean_section(config,key);
		return;
	}
	if (lf->url!=NULL){
		osip_from_to_str(lf->url,&tmp);
		if (tmp==NULL) {
			return;
		}
		lp_config_set_string(config,key,"url",tmp);
		osip_free(tmp);
	}
	lp_config_set_string(config,key,"pol",__policy_enum_to_str(lf->pol));
	lp_config_set_int(config,key,"subscribe",lf->subscribe);
	if (lf->proxy!=NULL){
		a=ms_list_index(lf->lc->sip_conf.proxies,lf->proxy);
		lp_config_set_int(config,key,"proxy",a);
	}else lp_config_set_int(config,key,"proxy",-1);
}
