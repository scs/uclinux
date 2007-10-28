/*      $Id: irexec.c,v 5.6 2003/06/07 22:12:52 lirc Exp $      */

/****************************************************************************
 ** irexec.c ****************************************************************
 ****************************************************************************
 *
 * irexec  - execute programs according to the pressed remote control buttons
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "lirc_client.h"

char *progname;
struct lirc_config *config;

void daemonize(void)
{
#ifdef DAEMONIZE
	if(daemon(0,0)==-1)
#endif
	{
		fprintf(stderr,"%s: can't daemonize\n",
			progname);
		perror(progname);
		lirc_freeconfig(config);
		lirc_deinit();
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	int do_daemon=0;
	char* program="irexec";

	progname="irexec " VERSION;
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"daemon",no_argument,NULL,'d'},
			{"name",required_argument,NULL,'n'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvdn:",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options] [config_file]\n",argv[0]);
			printf("\t -h --help\t\tdisplay usage summary\n");
			printf("\t -v --version\t\tdisplay version\n");
			printf("\t -d --daemon\t\trun in background\n");
			printf("\t -n --name\t\tuse this program name\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s\n",progname);
			return(EXIT_SUCCESS);
		case 'd':
			do_daemon=1;
			break;
		case 'n':
			program=optarg;
			break;
		default:
			printf("Usage: %s [options] [config_file]\n",argv[0]);
			return(EXIT_FAILURE);
		}
	}
	if (optind < argc-1)
	{
		fprintf(stderr,"%s: too many arguments\n",progname);
		return(EXIT_FAILURE);
	}
	
	if(lirc_init(program, do_daemon ? 0:1)==-1) exit(EXIT_FAILURE);

	if(lirc_readconfig(optind!=argc ? argv[optind]:NULL,&config,NULL)==0)
	{
		char *code;
		char *c;
		int ret;

		if(do_daemon) daemonize();
		while(lirc_nextcode(&code)==0)
		{
			if(code==NULL) continue;
			while((ret=lirc_code2char(config,code,&c))==0 &&
			      c!=NULL)
			{
#ifdef DEBUG
				if(!do_daemon)
				{
					printf("Execing command \"%s\"\n",c);
				}
#endif
				system(c);
			}
			free(code);
			if(ret==-1) break;
		}
		lirc_freeconfig(config);
	}

	lirc_deinit();
	exit(EXIT_SUCCESS);
}
