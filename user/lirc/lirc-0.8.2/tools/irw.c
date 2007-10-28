/*      $Id: irw.c,v 5.4 2002/08/17 11:17:41 lirc Exp $      */

/****************************************************************************
 ** irw.c *******************************************************************
 ****************************************************************************
 *
 * irw - watch the codes as lircd recognize them
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <getopt.h>

static struct option long_options[] =
{
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{0, 0, 0, 0}
};

int main(int argc,char *argv[])
{
	int fd,i;
	char buf[128];
	struct sockaddr_un addr;
	int c;
	char *progname;

	progname="irw " VERSION;

	addr.sun_family=AF_UNIX;

	while ((c = getopt_long(argc, argv, "hv", long_options, NULL))
	       != EOF) {
		switch (c){
		case 'h':
			printf("Usage: %s [socket]\n",argv[0]);
			printf("\t -h --help \t\tdisplay usage summary\n");
			printf("\t -v --version \t\tdisplay version\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s\n", progname);
			return(EXIT_SUCCESS);
		case '?':
			fprintf(stderr, "unrecognized option: -%c\n", optopt);
			fprintf(stderr, "Try `%s --help' for more "
				"information.\n",
				progname);
			return(EXIT_FAILURE);
		}
	}
	if(argc == optind){
		/* no arguments */
		strcpy(addr.sun_path,LIRCD);
	} else if (argc == optind+1){
		/* one argument */
		strcpy(addr.sun_path,argv[optind]);
	} else {
		fprintf(stderr, "%s: incorrect number of arguments.\n",
			progname);
		fprintf(stderr, "Try `%s --help' for more information.\n",
			progname);
		return(EXIT_FAILURE);
	}

	fd=socket(AF_UNIX,SOCK_STREAM,0);
	if(fd==-1)  {
		perror("socket");
		exit(errno);
	};
	if(connect(fd,(struct sockaddr *)&addr,sizeof(addr))==-1)  {
		perror("connect");
		exit(errno);
	};

	for(;;)  {
		i=read(fd,buf,128);
		if(i==-1)  {
			perror("read");
			exit(errno);
		};
		if(!i)  exit(0);
		write(STDOUT_FILENO,buf,i);
	};
}

