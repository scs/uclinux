/***************************************************************************
 *            authentication.c
 *
 *  Fri Jul 16 12:08:34 2004
 *  Copyright  2004  Simon MORLAT
 *  simon.morlat@linphone.org
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
#include "eXosip2.h"
#include "lpconfig.h"

extern LinphoneProxyConfig *linphone_core_get_proxy_config_from_rid(LinphoneCore *lc, int rid);
extern void linphone_proxy_config_set_realm(LinphoneProxyConfig *cfg, const char *realm);
extern void linphone_core_retry_proxy_register(LinphoneCore *lc, const char *realm);

LinphoneAuthInfo *linphone_auth_info_new(const char *username, const char *userid,
				   										const char *passwd, const char *ha1,const char *realm)
{
	LinphoneAuthInfo *obj=ms_new0(LinphoneAuthInfo,1);
	if (username!=NULL && (strlen(username)>0) ) obj->username=ms_strdup(username);
	if (userid!=NULL && (strlen(userid)>0)) obj->userid=ms_strdup(userid);
	if (passwd!=NULL && (strlen(passwd)>0)) obj->passwd=ms_strdup(passwd);
	if (ha1!=NULL && (strlen(ha1)>0)) obj->ha1=ms_strdup(ha1);
	if (realm!=NULL && (strlen(realm)>0)) obj->realm=ms_strdup(realm);
	return obj;
}

void linphone_auth_info_set_passwd(LinphoneAuthInfo *info, const char *passwd){
	if (info->passwd!=NULL) {
		ms_free(info->passwd);
		info->passwd=NULL;
	}
	if (passwd!=NULL && (strlen(passwd)>0)) info->passwd=ms_strdup(passwd);
}

void linphone_auth_info_destroy(LinphoneAuthInfo *obj){
	if (obj->username!=NULL) ms_free(obj->username);
	if (obj->userid!=NULL) ms_free(obj->userid);
	if (obj->passwd!=NULL) ms_free(obj->passwd);
	if (obj->ha1!=NULL) ms_free(obj->ha1);
	if (obj->realm!=NULL) ms_free(obj->realm);
	ms_free(obj);
}

void linphone_auth_info_write_config(LpConfig *config, LinphoneAuthInfo *obj, int pos)
{
	char key[50];
	sprintf(key,"auth_info_%i",pos);
	lp_config_clean_section(config,key);
	
	if (obj==NULL){
		return;
	}		
	if (obj->username!=NULL){
		lp_config_set_string(config,key,"username",obj->username);
	}
	if (obj->userid!=NULL){
		lp_config_set_string(config,key,"userid",obj->userid);
	}
	if (obj->passwd!=NULL){
		lp_config_set_string(config,key,"passwd",obj->passwd);
	}
	if (obj->ha1!=NULL){
		lp_config_set_string(config,key,"ha1",obj->ha1);
	}
	if (obj->realm!=NULL){
		lp_config_set_string(config,key,"realm",obj->realm);
	}
	lp_config_sync(config);
}

LinphoneAuthInfo *linphone_auth_info_new_from_config_file(LpConfig * config, int pos)
{
	char key[50];
	const char *username,*userid,*passwd,*ha1,*realm;
	
	sprintf(key,"auth_info_%i",pos);
	if (!lp_config_has_section(config,key)){
		return NULL;
	}
	
	username=lp_config_get_string(config,key,"username",NULL);
	userid=lp_config_get_string(config,key,"userid",NULL);
	passwd=lp_config_get_string(config,key,"passwd",NULL);
	ha1=lp_config_get_string(config,key,"ha1",NULL);
	realm=lp_config_get_string(config,key,"realm",NULL);
	return linphone_auth_info_new(username,userid,passwd,ha1,realm);
}

static bool_t key_match(const char *tmp1, const char *tmp2){
	if (tmp1==NULL && tmp2==NULL) return TRUE;
	if (tmp1!=NULL && tmp2!=NULL && strcmp(tmp1,tmp2)==0) return TRUE;
	return FALSE;
	
}

static int auth_info_compare(const void *pinfo,const void *pref){
	LinphoneAuthInfo *info=(LinphoneAuthInfo*)pinfo;
	LinphoneAuthInfo *ref=(LinphoneAuthInfo*)pref;
	if (key_match(info->realm,ref->realm) && key_match(info->username,ref->username)) return 0;
	return -1;
}

LinphoneAuthInfo *linphone_core_auth_info_find(LinphoneCore *lc, const char *realm, const char *username)
{
	LinphoneAuthInfo ref;
	MSList *elem;
	ref.realm=(char*)realm;
	ref.username=(char*)username;
	elem=ms_list_find_custom(lc->auth_info,auth_info_compare,(void*)&ref);
	if (elem==NULL) return NULL;
	return (LinphoneAuthInfo*)elem->data;
}

void linphone_core_add_auth_info(LinphoneCore *lc, LinphoneAuthInfo *info)
{
	int n;
	MSList *elem;
	char *userid;
	if (info->userid==NULL || info->userid[0]=='\0') userid=info->username;
	else userid=info->userid;
	eXosip_lock();
	eXosip_add_authentication_info(info->username,userid,
				info->passwd,info->ha1,info->realm);
	eXosip_unlock();
	/* find if we are attempting to modify an existing auth info */
	elem=ms_list_find_custom(lc->auth_info,auth_info_compare,info);
	if (elem!=NULL){
		linphone_auth_info_destroy((LinphoneAuthInfo*)elem->data);
		elem->data=(void *)info;
		n=ms_list_position(lc->auth_info,elem);
	}else {
		lc->auth_info=ms_list_append(lc->auth_info,(void *)info);
		n=ms_list_size(lc->auth_info)-1;
	}
	/* find if we need to restart a register request */
	linphone_core_retry_proxy_register(lc,info->realm);
}

void linphone_core_remove_auth_info(LinphoneCore *lc, LinphoneAuthInfo *info){
	int len=ms_list_size(lc->auth_info);
	int newlen;
	int i;
	MSList *elem;
	lc->auth_info=ms_list_remove(lc->auth_info,info);
	newlen=ms_list_size(lc->auth_info);
	/*printf("len=%i newlen=%i\n",len,newlen);*/
	linphone_auth_info_destroy(info);
	for (i=0;i<len;i++){
		linphone_auth_info_write_config(lc->config,NULL,i);
	}
	for (elem=lc->auth_info,i=0;elem!=NULL;elem=ms_list_next(elem),i++){
		linphone_auth_info_write_config(lc->config,(LinphoneAuthInfo*)elem->data,i);
	}
	
}

void linphone_core_clear_all_auth_info(LinphoneCore *lc){
	MSList *elem;
	int i;
	eXosip_lock();
	eXosip_clear_authentication_info();
	eXosip_unlock();
	for(i=0,elem=lc->auth_info;elem!=NULL;elem=ms_list_next(elem),i++){
		LinphoneAuthInfo *info=(LinphoneAuthInfo*)elem->data;
		linphone_auth_info_destroy(info);
		linphone_auth_info_write_config(lc->config,NULL,i);
	}
	ms_list_free(lc->auth_info);
	lc->auth_info=NULL;
}

bool_t linphone_core_find_or_ask_for_auth_info(LinphoneCore *lc,const char *username,const char* realm, bool_t force_ask)
{
	if (force_ask || linphone_core_auth_info_find(lc,realm,username)==NULL){
		if (lc->vtable.auth_info_requested!=NULL) {
			lc->vtable.auth_info_requested(lc,realm,username);
		}
		return FALSE;
	}else{
		return TRUE;
	}
}

bool_t linphone_process_authentication(LinphoneCore *lc, osip_message_t *resp, LinphoneProxyConfig *cfg, bool_t force_ask)
{
	char *prx_realm=NULL,*www_realm=NULL;
	osip_proxy_authenticate_t *prx_auth;
	osip_www_authenticate_t *www_auth;
	char *username;
	bool_t have_it=TRUE;
	
	username=osip_uri_get_username(resp->from->url);
	prx_auth=(osip_proxy_authenticate_t*)osip_list_get(resp->proxy_authenticates,0);
	www_auth=(osip_proxy_authenticate_t*)osip_list_get(resp->www_authenticates,0);
	if (prx_auth!=NULL)
		prx_realm=osip_proxy_authenticate_get_realm(prx_auth);
	if (www_auth!=NULL)
		www_realm=osip_www_authenticate_get_realm(www_auth);
	
	if (prx_realm==NULL && www_realm==NULL){
		ms_warning("No realm in the server response.");
		return FALSE;
	}
	if (cfg!=NULL) {
		if (prx_realm!=NULL)
			linphone_proxy_config_set_realm(cfg,prx_realm);
		else if (www_realm!=NULL)
			linphone_proxy_config_set_realm(cfg,www_realm);
	}
	/* see if we already have this auth information , not to ask it everytime to the user */
	if (prx_realm!=NULL) 
		have_it=linphone_core_find_or_ask_for_auth_info(lc,username,prx_realm,force_ask);
	if (www_realm!=NULL) 
		have_it=linphone_core_find_or_ask_for_auth_info(lc,username,www_realm, force_ask) && have_it;
	return have_it;
}

void linphone_register_authentication_required(LinphoneCore *lc,eXosip_event_t *ev){
	osip_message_t *resp;
	LinphoneProxyConfig *cfg;
	eXosip_reg_t *reg=eXosip_event_get_reginfo(ev);
	ms_return_if_fail(reg!=NULL);
	
	resp=reg->r_last_tr->last_response;
	ms_return_if_fail(resp!=NULL);
	cfg=linphone_core_get_proxy_config_from_rid(lc,ev->rid);
	ms_return_if_fail(cfg!=NULL);
	if (linphone_process_authentication(lc,resp,cfg,cfg->auth_pending)){
		/* we have the information, so retry the register */
		eXosip_lock();
		eXosip_register(ev->rid,-1);
		eXosip_unlock();
	}
	cfg->auth_pending=TRUE;
}

void linphone_invite_authentication_required(LinphoneCore* lc,LinphoneCall *lcall)
{
	osip_message_t *resp;
	eXosip_call_t *call=NULL;
	eXosip_call_find(lcall->cid,&call);
	ms_return_if_fail(call!=NULL);
	resp=call->c_out_tr->last_response;
	ms_return_if_fail(resp!=NULL);
	if (linphone_process_authentication(lc,resp,NULL,lcall->auth_pending)){
		eXosip_lock();
		eXosip_retry_call(lcall->cid);
		eXosip_unlock();
	}else{
		linphone_call_destroy(lcall);
		lc->call=NULL;
	}
	
}
