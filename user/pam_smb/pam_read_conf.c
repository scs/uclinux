#include <stdio.h>
#include <string.h>

#define CONFFILE "/etc/config/pam_smb.conf"

/***********************************************************************
	This file is (C) Dave Airlie 1997 ( David.Airlie@ul.ie ) 
	and is covered by the GPL provided in the COPYING FILE.
***********************************************************************/
int smb_readpamconf(char *smb_server, char *smb_backup, char *smb_domain);

int smb_readpamconf(char *smb_server, char *smb_backup, char *smb_domain)
{
	FILE *fl;
		
	int len;
	if (!(fl=fopen(CONFFILE,"r")))
	{
		return 1;
	}
	
	fgets(smb_domain, 50, fl); 
	len=strlen(smb_domain);
	smb_domain[len-1]='\0';
	fgets(smb_server, 50, fl);
	len=strlen(smb_server);
	smb_server[len-1]='\0';
	fgets(smb_backup, 50, fl);
	len=strlen(smb_backup);
	smb_backup[len-1]='\0';
	fclose(fl);
	return(0);
}

