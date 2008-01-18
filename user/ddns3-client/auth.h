/*
 *	DDNS v3 Client
 *
 *		Author:		Alan Yates <alany@ay.com.au>
 *		Version:	$Id: auth.h 1009 2005-07-25 01:53:52Z magicyang $
 */

#ifndef _AUTH_H
#define _AUTH_H

#include "ctx.h"

struct ddns3_auth {
	char *name;
	int (*makechallenge)(struct ddns3_ctx *c, char *user, char *passwd);
};

int ddns3_auth_makechallenge(struct ddns3_ctx *c, char *auth, char *user, char *passwd);

#endif /* _AUTH_H */
