/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Authorization "module" (c) 1998,99 Martin Hinner <martin@tdp.cz>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifdef USE_AUTH
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>

#include <config/autoconf.h>

#ifndef HOSTBUILD
#ifdef CONFIG_USER_OLD_PASSWORDS
#include <crypt_old.h>
#endif
#endif

#ifdef CONFIG_AMAZON
#include "../../login/logcnt.c"
#endif

#include "base64.h"

#ifdef AUTH_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <errno.h>
#endif

/*#undef DEBUG*/

#ifdef DEBUG
#define DBG(A) A
#else
#define DBG(A)
#endif

struct _auth_dir_ {
	char *directory;
#ifndef AUTH_PAM
	FILE *authfile;
#endif
	int dir_len;
	struct _auth_dir_ *next;
};

typedef struct _auth_dir_ auth_dir;

static auth_dir *auth_list = 0;

/*
 * Name: auth_add
 *
 * Description: adds 
 */
void auth_add(char *directory,char *file)
{
	auth_dir *new_a,*old;
	
	old = auth_list;
	while (old)
	{
		if (!strcmp(directory,old->directory))
			return;
		old = old->next;
	}

	new_a = (auth_dir *)malloc(sizeof(auth_dir));
	/* success of this call will be checked later... */
#ifndef AUTH_PAM
	new_a->authfile = fopen(file,"rt");
#endif
	new_a->directory = strdup(directory);
	new_a->dir_len = strlen(directory);
	new_a->next = auth_list;
	auth_list = new_a;
}

#ifndef AUTH_PAM
/*
 * Name: auth_check_userpass
 *
 * Description: Checks user's password.
 *  Return 0 if OK, 1 if bad password or 2 if unknown user
 * 	is ok, else returns nonzero.
 *  The format of the file is:
 *  login:crypt(passwd)[:id]
 *
 * Note that there can be multiple entries with the *same* login
 * but possibly different password and id, so if we don't match
 * the password of the first entry, we keep going.
 */
static int auth_check_userpass(char *user,char *pass,FILE *fh, char idbuf[15])
{
	int ret = 2;

	char buf[128];

	while (fgets(buf, sizeof(buf), fh)) {
		char *pt;
		char *id;
		char *pw = strchr(buf, ':');

		if (!pw) {
			continue;
		}
		*pw++ = 0;

		if (strcmp(user, buf) != 0) {
			/* No match on user */
			continue;
		}

		/* Make sure we strip the trailing newline */
		if ((pt = strchr(pw, '\n')) != 0) {
			*pt = 0;
		}

		/* There might be an id too */
		id = strchr(pw, ':');
		if (id) {
			*id++ = 0;
		}
		else {
			id = "";
		}

#ifndef HOSTBUILD
#ifdef CONFIG_USER_OLD_PASSWORDS
		if (strcmp(crypt_old(pass, pw), pw) == 0) {
			/* Matched password */
		}
		else
#endif
#endif

		if (strcmp(crypt(pass, pw), pw) != 0) {
			/* Bad password */
			ret = 1;
			/* But keep going, because we may find the same username later
			 * with a different password
			 */
			continue;
		}

		/* We have a match, so remember the id */
		ret = 0;
		snprintf(idbuf, 15, "%s", id);
		break;
	}

	return ret;
}
#else

static const char *pam_pw;

static int myconv(int n, const struct pam_message **m, struct pam_response **r, void *nul) {
	if (n != 1 || m[0]->msg_style != PAM_PROMPT_ECHO_OFF) {
		syslog(LOG_ERR, "unexpected PAM conversation: %d/%s\n", m[0]->msg_style, m[0]->msg);
		return PAM_CONV_ERR;
	}
	*r = malloc(sizeof(struct pam_response));
	if (*r == NULL) {
		syslog(LOG_ERR, "out of memory in PAM conversation: %d", errno);
		return PAM_CONV_ERR;
	}
	(*r)[0].resp = strdup(pam_pw);
	(*r)[0].resp_retcode = 0;
	return ((*r)[0].resp != NULL)?PAM_SUCCESS:PAM_CONV_ERR;
}

static struct pam_conv conv = {
	&myconv,
	NULL
};

static int auth_check_pam(const char *user, const char *pass, char idbuf[15]) {
	int r, result;
	pam_handle_t *pamh = NULL;

	pam_pw = pass;

	r = pam_start("fnord", user, &conv, &pamh);
	if (r != PAM_SUCCESS) {
		syslog(LOG_ERR, "couldn't initialise PAM: %s", pam_strerror (pamh, r));
		return 3;
	}

	r = pam_set_item(pamh, PAM_USER, user);
	if (r != PAM_SUCCESS) {
		syslog(LOG_ERR, "couldn't set username: %s", pam_strerror (pamh, r));
err3:			result = 3;
err:			pam_end(pamh, r);
		return result;
	}

	r = pam_set_item(pamh, PAM_CONV, &conv);
	if (r != PAM_SUCCESS) {
		syslog(LOG_ERR, "couldn't set conv: %s", pam_strerror (pamh, r));
		goto err3;
	}

	r = pam_authenticate(pamh, 0);
	if (r == PAM_AUTH_ERR) {
		syslog(LOG_ERR, "couldn't authenticate: %s", pam_strerror (pamh, r));
		pam_fail_delay (pamh, 1000000);
		result = 1;
		goto err;
	}
	if (r == PAM_SUCCESS) {
		const char *id = pam_getenv(pamh, "USER_AUTHBY");
		if (id != NULL) {
			strncpy(idbuf, id, 14);
			idbuf[14] = '\0';
		} else
			idbuf[0] = '\0';
		pam_end(pamh, r);
		return 0;
	}
	syslog(LOG_ERR, "unable to authenticate");
	pam_end(pamh, r);
	return 3;
}

#endif

int auth_authorize(const char *host, const char *url, const char *remote_ip_addr, const char *authorization, char username[15], char id[15])
{
	auth_dir *current;
	char *pwd;
	char auth_userpass[0x80];

	current = auth_list;

	while (current) {
		if (!memcmp(url, current->directory,
								current->dir_len)) {
			if (current->directory[current->dir_len - 1] != '/' &&
								url[current->dir_len] != '/' &&
								url[current->dir_len] != '\0') {
				break;
			}

			if (authorization) {
#ifndef AUTH_PAM
				if (current->authfile==0) {
					return 0;
				}
#endif
				if (strncasecmp(authorization,"Basic ",6)) {
					syslog(LOG_ERR, "Can only handle Basic auth\n");
					return 0;
				}
				
				base64decode(auth_userpass,authorization+6,sizeof(auth_userpass));
				
				if ( (pwd = strchr(auth_userpass,':')) == 0 ) {
					syslog(LOG_ERR, "No user:pass in Basic auth\n");
					return 0;
				}
				
				*pwd++=0;
#ifdef AUTH_PAM
				const int denied = auth_check_pam(auth_userpass, pwd, id);
#else
				rewind(current->authfile);

				const int denied = auth_check_userpass(auth_userpass,pwd,current->authfile, id);
#endif
#ifdef CONFIG_AMAZON
				access__attempted(denied, auth_userpass);
#endif
				if (denied) {
					switch (denied) {
						case 1:
							syslog(LOG_ERR, "Authentication attempt failed for %s from %s because: Bad Password\n",
									auth_userpass, remote_ip_addr);
							break;
						case 2:
							syslog(LOG_ERR, "Authentication attempt failed for %s from %s because: Invalid Username\n",
									auth_userpass, remote_ip_addr);
					}
					return 0;
				}
				/* Rely on syslogd to throw away duplicates */
				syslog(LOG_INFO, "Authentication successful for %s from %s\n", auth_userpass, remote_ip_addr);

				/* Copy user's name to request structure */
				snprintf(username, 15, "%s", auth_userpass);
				return 1;
			}
			else {
				/* No credentials were supplied. Tell them that some are required */
				return 0;
			}
		}
		current = current->next;
	}
						
	return 1;
}

#if 0
void dump_auth(void)
{
	auth_dir *temp;

	temp = auth_list;
	while (temp) {
		auth_dir *temp_next;

		if (temp->directory)
			free(temp->directory);
		if (temp->authfile)
			fclose(temp->authfile);
		temp_next = temp->next;
		free(temp);
		temp = temp_next;
	}
	auth_list = 0;
}
#endif

#endif
