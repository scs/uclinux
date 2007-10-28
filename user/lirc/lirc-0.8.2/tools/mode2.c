/*      $Id: mode2.c,v 5.14 2006/01/02 19:33:52 lirc Exp $      */

/****************************************************************************
 ** mode2.c *****************************************************************
 ****************************************************************************
 *
 * mode2 - shows the pulse/space length of a remote button
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <limits.h>

#include "drivers/lirc.h"
#include "daemons/ir_remote.h"

int main(int argc,char **argv)
{
	int fd;
	char buffer[sizeof(ir_code)];
	lirc_t data;
	unsigned long mode;
	char *device=LIRC_DRIVER_DEVICE;
	char *progname;
	struct stat s;
	int dmode=0;
	unsigned long code_length;
	size_t count=sizeof(lirc_t);
	int i;
	
	progname="mode2";
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"device",required_argument,NULL,'d'},
			{"mode",no_argument,NULL,'m'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvd:m",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options]\n",progname);
			printf("\t -h --help\t\tdisplay usage summary\n");
			printf("\t -v --version\t\tdisplay version\n");
			printf("\t -d --device=device\tread from given device\n");
			printf("\t -m --mode\t\tenable alternative display mode\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s %s\n",progname, VERSION);
			return(EXIT_SUCCESS);
		case 'd':
			device=optarg;
			break;
		case 'm':
			dmode=1;
			break;
		default:
			printf("Usage: %s [options]\n",progname);
			return(EXIT_FAILURE);
		}
	}
	if (optind < argc)
	{
		fprintf(stderr,"%s: too many arguments\n",progname);
		return(EXIT_FAILURE);
	}
	
	fd=open(device,O_RDONLY);
	if(fd==-1)  {
		fprintf(stderr,"%s: error opening %s\n",progname,device);
		perror(progname);
		exit(EXIT_FAILURE);
	};

	if ( (fstat(fd,&s)!=-1) && (S_ISFIFO(s.st_mode)) )
	{
		/* can't do ioctls on a pipe */
	}
	else if ( (fstat(fd,&s)!=-1) && (!S_ISCHR(s.st_mode)) )
	{
		fprintf(stderr,"%s: %s is not a character device\n",progname,device);
		fprintf(stderr,"%s: use the -d option to specify the correct device\n",progname);
		close(fd);
		exit(EXIT_FAILURE);
	}
	else if(ioctl(fd,LIRC_GET_REC_MODE,&mode)==-1)
	{
		printf("This program is only intended for receivers "
		       "supporting the pulse/space layer.\n");
		printf("Note that this is no error, but this program simply "
		       "makes no sense for your\n"
		       "receiver.\n");
		printf("In order to test your setup run lircd with the "
		       "--nodaemon option and \n"
		       "then check if the remote works with the irw tool.\n");
		close(fd);
		exit(EXIT_FAILURE);
	}
	if(mode==LIRC_MODE_CODE)
	{
		count = 1;
	}
	else if(mode==LIRC_MODE_LIRCCODE)
	{
		if(ioctl(fd,LIRC_GET_LENGTH,&code_length)==-1)
		{
			fprintf(stderr, "%s: could not get code length\n",
				progname);
			perror(progname);
			close(fd);
			exit(EXIT_FAILURE);
		}
		if(code_length>sizeof(ir_code)*CHAR_BIT)
		{
			fprintf(stderr, "%s: cannot handle %lu bit codes\n",
				progname, code_length);
			close(fd);
			exit(EXIT_FAILURE);
		}
		count = (code_length+CHAR_BIT-1)/CHAR_BIT;
	}
	while(1)
	{
		int result;

		result=read(fd,(mode==LIRC_MODE_MODE2 ? (void *) &data:buffer),count);
		if(result!=count)
		{
			fprintf(stderr,"read() failed\n");
			break;
		}
		
		if(mode!=LIRC_MODE_MODE2)
		{
			printf("code: 0x");
			for(i=0; i<count; i++)
			{
				printf("%02x", (unsigned char) buffer[i]);
			}
			printf("\n");
			fflush(stdout);
			continue;
		}

		if (!dmode)
		{
			printf("%s %lu\n",(data&PULSE_BIT)?"pulse":"space",
			       (unsigned long) (data&PULSE_MASK));
		}
		else
		{
			static int bitno = 1;
			
			/* print output like irrecord raw config file data */
			printf(" %8lu" , (unsigned long) data&PULSE_MASK);
			++bitno;
			if (data&PULSE_BIT)
			{
				if ((bitno & 1) == 0)
				{
					/* not in expected order */
					printf("-pulse");
				}
			}
			else
			{
				if (bitno & 1)
				{
					/* not in expected order */
					printf("-space");
				}
				if ( ((data&PULSE_MASK) > 50000) ||
				     (bitno >= 6) )
				{
					/* real long space or more
                                           than 6 codes, start new line */
					printf("\n");  
					if ((data&PULSE_MASK) > 50000)
						printf("\n");
					bitno = 0;
				}
			}
		}
		fflush(stdout);
	};
	return(EXIT_SUCCESS);
}
