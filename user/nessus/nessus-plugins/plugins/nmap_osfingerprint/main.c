/*
 * This plugin is a stripped down version of nmap, which does not
 * use 12Mb of RAM while being used.
 */
 
/***********************************************************************
 * main.c -- Contains the main() function of Nmap.  Note that main()   *
 * does very little except for calling nmap_main() (which is in        *
 * nmap.c)                                                             *
 *                                                                     *
 ***********************************************************************
 *  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
 *  program is free software; you can redistribute it and/or modify    *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; Version 2.  This guarantees your  *
 *  right to use, modify, and redistribute this software under certain *
 *  conditions.  If this license is unacceptable to you, we may be     *
 *  willing to sell alternative licenses (contact sales@insecure.com). *
 *                                                                     *
 *  If you received these files with a written license agreement       *
 *  stating terms other than the (GPL) terms above, then that          *
 *  alternative license agreement takes precendence over this comment. *
 *                                                                     *
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port Nmap to new platforms, fix     *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
 *  General Public License for more details (                          *
 *  http://www.gnu.org/copyleft/gpl.html ).                            *
 *                                                                     *
 ***********************************************************************/

/* $Id: main.c,v 1.5 2003/10/01 16:00:11 renaud Exp $ */

#include "nmap.h"


#define EN_NAME "OS fingerprint"
#define EN_DESC "\
This plugin determines which operating system\n\
the remote host is running.\n\n\
Guessing the remote operating system allows\n\
an attacker to make more focuses attacks and\n\
to achieve his goal more quickly\n\
This plugin uses the code from Nmap - see www.nmap.org\n\
Risk factor : None"

#define COPYRIGHT "Nmap is (C) Fyodor - <fyodor@insecure.org> / Plugin-ified by Xueyong Zhi <zhi@mail.eecis.udel.edu>"
#define EN_SUMMARY "Performs OS recognition"
#define EN_FAMILY "General"


PlugExport int 
plugin_init(struct arglist * desc)
{
	plug_set_id(desc, 11268);

	plug_set_version(desc, "$Revision: 1.5 $");
	plug_set_name(desc, EN_NAME, NULL);
	plug_set_summary(desc, EN_SUMMARY, NULL);
	plug_set_description(desc, EN_DESC, NULL);
	plug_set_copyright(desc, COPYRIGHT, NULL);

	/*
	 * Some IP stacks out there don't really like
	 * Nmap's fingerprinting method.
	 */
	plug_set_category(desc, ACT_DESTRUCTIVE_ATTACK);
	plug_set_family(desc, EN_FAMILY, NULL);
	plug_set_cve_id(desc, "CAN-1999-0454");
	return (0);
}

PlugExport int
plugin_run(struct arglist * desc)
{
 struct in_addr * ip = plug_get_host_ip(desc);
 char * ip_name = strdup(inet_ntoa(*ip));
 int i;
 int open_port = plug_get_host_open_port(desc);
 int closed_port = 0;
 
  /* The "real" main is nmap_main().  This function hijacks control at the
     beginning and then just call nmap_main */


  struct timeval tv;

  /* You never know when "random" numbers will come in handy ... */
  gettimeofday(&tv, NULL);

  srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());

  /* initialize our options */
  options_init();

  /* Trap these sigs for cleanup */
#if HAVE_SIGNAL
   signal(SIGINT, sigdie);
   signal(SIGTERM, sigdie);
   signal(SIGHUP, sigdie);
   signal(SIGCHLD, reaper);
#endif
 
 if(open_port <= 0)return 0; 
 
 if(open_port > 1)
 	closed_port = open_port - 1;
 else {
   for(i=1;i<20;i++)
   {
    if(host_get_port_state(desc, i) == 0)
    	{
	closed_port = i;
	break;
	}
   }
 }
 
 nmap_main(open_port, closed_port, ip_name, desc);
 free(ip_name);
 return 0;
}

#if 0
int main(int argc, char *argv[])
{

	/* The "real" main is nmap_main().  This function hijacks control at the
	   beginning and then just call nmap_main */
	int ret;

	struct timeval tv;

	/* You never know when "random" numbers will come in handy ... */
	gettimeofday(&tv, NULL);

	srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());

	/* initialize our options */
	options_init();


	ret = nmap_main(22, 1, "10.163.156.15");

	return ret;
}
#endif


int Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  if (dest[n-1] == '\0')
    return 0;
  dest[n-1] = '\0';
  return -1;
}
