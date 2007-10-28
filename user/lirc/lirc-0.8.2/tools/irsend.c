/* 	$Id: irsend.c,v 5.4 2007/04/06 19:31:45 lirc Exp $	 */

/*
  
  irsend -  application for sending IR-codes via lirc
  
  Copyright (C) 1998 Christoph Bartelmus (lirc@bartelmus.de)
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>

#define PACKET_SIZE 256
/* three seconds */
#define TIMEOUT 3

int timeout=0;
char *progname;

void sigalrm(int sig)
{
	timeout=1;
}

const char *read_string(int fd)
{
	static char buffer[PACKET_SIZE+1]="";
	char *end;
	static int ptr=0;
	ssize_t ret;
		
	if(ptr>0)
	{
		memmove(buffer,buffer+ptr,strlen(buffer+ptr)+1);
		ptr=strlen(buffer);
		end=strchr(buffer,'\n');
	}
	else
	{
		end=NULL;
	}
	alarm(TIMEOUT);
	while(end==NULL)
	{
		if(PACKET_SIZE<=ptr)
		{
			fprintf(stderr,"%s: bad packet\n",progname);
			ptr=0;
			return(NULL);
		}
		ret=read(fd,buffer+ptr,PACKET_SIZE-ptr);

		if(ret<=0 || timeout)
		{
			if(timeout)
			{
				fprintf(stderr,"%s: timeout\n",progname);
			}
			else
			{
				alarm(0);
			}
			ptr=0;
			return(NULL);
		}
		buffer[ptr+ret]=0;
		ptr=strlen(buffer);
		end=strchr(buffer,'\n');
	}
	alarm(0);timeout=0;

	end[0]=0;
	ptr=strlen(buffer)+1;
#       ifdef DEBUG
	printf("buffer: -%s-\n",buffer);
#       endif
	return(buffer);
}

enum packet_state
{
	P_BEGIN,
	P_MESSAGE,
	P_STATUS,
	P_DATA,
	P_N,
	P_DATA_N,
	P_END
};

int send_packet(int fd,const char *packet)
{
	int done,todo;
	const char *string,*data;
	char *endptr;
	enum packet_state state;
	int status,n;
	unsigned long data_n=0;

	todo=strlen(packet);
	data=packet;
	while(todo>0)
	{
		done=write(fd,(void *) data,todo);
		if(done<0)
		{
			fprintf(stderr,"%s: could not send packet\n",
				progname);
			perror(progname);
			return(-1);
		}
		data+=done;
		todo-=done;
	}

	/* get response */
	status=0;
	state=P_BEGIN;
	n=0;
	while(1)
	{
		string=read_string(fd);
		if(string==NULL) return(-1);
		switch(state)
		{
		case P_BEGIN:
			if(strcasecmp(string,"BEGIN")!=0)
			{
				continue;
			}
			state=P_MESSAGE;
			break;
		case P_MESSAGE:
			if(strncasecmp(string,packet,strlen(string))!=0 ||
			   strlen(string)+1!=strlen(packet))
			{
				state=P_BEGIN;
				continue;
			}
			state=P_STATUS;
			break;
		case P_STATUS:
			if(strcasecmp(string,"SUCCESS")==0)
			{
				status=0;
			}
			else if(strcasecmp(string,"END")==0)
			{
				status=0;
				return(status);
			}
			else if(strcasecmp(string,"ERROR")==0)
			{
				fprintf(stderr,"%s: command failed: %s",
					progname,packet);
				status=-1;
			}
			else
			{
				goto bad_packet;
			}
			state=P_DATA;
			break;
		case P_DATA:
			if(strcasecmp(string,"END")==0)
			{
				return(status);
			}
			else if(strcasecmp(string,"DATA")==0)
			{
				state=P_N;
				break;
			}
			goto bad_packet;
		case P_N:
			errno=0;
			data_n=strtoul(string,&endptr,0);
			if(!*string || *endptr)
			{
				goto bad_packet;
			}
			if(data_n==0)
			{
				state=P_END;
			}
			else
			{
				state=P_DATA_N;
			}
			break;
		case P_DATA_N:
			fprintf(stderr,"%s: %s\n",progname,string);
			n++;
			if(n==data_n) state=P_END;
			break;
		case P_END:
			if(strcasecmp(string,"END")==0)
			{
				return(status);
			}
			goto bad_packet;
			break;
		}
	}
 bad_packet:
	fprintf(stderr,"%s: bad return packet\n",progname);
	return(-1);
}

int main(int argc,char **argv)
{
	char *directive;
	char *remote;
	char *code;
        char *lircd=NULL;
	char *address=NULL;
	unsigned short port = LIRC_INET_PORT;
	unsigned long count=1;
	struct sockaddr_un addr_un;
	struct sockaddr_in addr_in;
	int fd;
	char buffer[PACKET_SIZE+1];
	struct sigaction act;
	
	progname = "irsend";
	
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
                        {"device",required_argument,NULL,'d'},
                        {"address",required_argument,NULL,'a'},
                        {"count",required_argument,NULL,'#'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvd:a:#:",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options] DIRECTIVE REMOTE CODE [CODE...]\n",progname);
			printf("\t -h --help\t\t\tdisplay usage summary\n");
			printf("\t -v --version\t\t\tdisplay version\n");
                        printf("\t -d --device\t\t\tuse given lircd socket [%s]\n", LIRCD);
                        printf("\t -a --address=host[:port]\tconnect to "
			       "lircd at this address\n");
                        printf("\t -# --count=n\t\t\tsend command n times\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s %s\n", progname, VERSION);
			return(EXIT_SUCCESS);
                case 'd':
                        lircd = optarg;
                        break;
		case 'a':
		{
			char *p;
			char *end;
			unsigned long val;
			
			address = strdup(optarg);
			if(!address)
			{
				fprintf(stderr, "%s: out of memory\n",
					progname);
				return(EXIT_FAILURE);
			}
			p = strchr(address, ':');
			if(p != NULL)
		        {
				val = strtoul(p+1, &end, 10);
				if (!(*(p+1)) || *end ||
				    val<1 || val>USHRT_MAX)
				{
					fprintf(stderr,
						"%s: invalid port number: "
						"%s\n", progname, p+1);
					return(EXIT_FAILURE);
				}
				port = (unsigned short) val;
				*p = 0;
			}
			break;
		}
		case '#':
		{
			char *end;
			
			count = strtoul(optarg, &end, 10);
			if(!*optarg || *end)
			{
				fprintf(stderr, "%s: invalid count value: "
					"%s\n", progname, optarg);
				return(EXIT_FAILURE);
			}
			break;
		}
		default:
			return(EXIT_FAILURE);
		}
	}
	if (optind + 2 > argc)
	{
		fprintf(stderr,"%s: not enough arguments\n",progname);
		return(EXIT_FAILURE);
	}
	
	if(lircd==NULL)
	{
		lircd=LIRCD;
	}
        else
	{
                if(strlen(lircd)+1 > sizeof(addr_un.sun_path))
		{
			/* lircd is longer than sockaddr_un.sun_path field */
			fprintf(stderr, "%s: socket name is too long\n",
				progname);
			return(EXIT_FAILURE);
                }
	}
	
	act.sa_handler=sigalrm;
	sigemptyset(&act.sa_mask);
	act.sa_flags=0;           /* we need EINTR */
	sigaction(SIGALRM,&act,NULL);

	if (address == NULL) {
		addr_un.sun_family=AF_UNIX;
		strcpy(addr_un.sun_path,lircd);
		fd=socket(AF_UNIX,SOCK_STREAM,0);
	}
	else
	{
		struct hostent *hostInfo;
		
		hostInfo = gethostbyname(address);
		if (hostInfo == NULL) {
			fprintf(stderr,"%s: host %s unknown\n", progname,
				address);
	  		return(EXIT_FAILURE);
		}
		addr_in.sin_family = hostInfo->h_addrtype;
		memcpy((char *) &addr_in.sin_addr.s_addr,
		       hostInfo->h_addr_list[0], hostInfo->h_length);
		addr_in.sin_port = htons(port);
		fd=socket(AF_INET,SOCK_STREAM,0);	
	}

	if(fd==-1)
	{
		fprintf(stderr,"%s: could not open socket\n",progname);
		perror(progname);
		exit(EXIT_FAILURE);
	};
	
	if(connect(fd,
		   address ? (struct sockaddr *) &addr_in :
		   (struct sockaddr *) &addr_un,
		   address ? sizeof(addr_in) : sizeof(addr_un)) == -1)
	{
		fprintf(stderr,"%s: could not connect to socket\n",progname);
		perror(progname);
		exit(EXIT_FAILURE);
	};
	
	if(address) free(address);
	address = NULL;
	
	directive=argv[optind++];

	if(strcasecmp(directive,"set_transmitters")==0)
	{
		code=argv[optind++];
		if (strlen(directive)+strlen(code)+2<PACKET_SIZE)
		{
			sprintf(buffer,"%s %s",directive,code);
		}
		else
		{
			fprintf(stderr,"%s: input too long\n",progname);
			exit(EXIT_FAILURE);
		}
		while(optind<argc)
		{
			code=argv[optind++];
			if (strlen(buffer)+strlen(code)+2<PACKET_SIZE)
			{
				sprintf(buffer+strlen(buffer)," %s",code);
			}
			else
			{
				fprintf(stderr,"%s: input too long\n",progname);
				exit(EXIT_FAILURE);
			}
		}
		strcat(buffer,"\n");
		if(send_packet(fd,buffer)==-1)
		{
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		remote=argv[optind++];

		if (optind==argc)
		{
			fprintf(stderr,"%s: not enough arguments\n",progname);
			exit(EXIT_FAILURE);
		}
		while(optind<argc)
		{
			code=argv[optind++];
		
			if(strlen(directive)+strlen(remote)+strlen(code)+3<PACKET_SIZE)
			{
				if(strcasecmp(directive,"SEND_ONCE")==0 && count>1)
				{
					sprintf(buffer,"%s %s %s %lu\n",
						directive,remote,code,count);
				}
				else
				{
					sprintf(buffer,"%s %s %s\n",directive,remote,code);
				}
				if(send_packet(fd,buffer)==-1)
				{
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				fprintf(stderr,"%s: input too long\n",progname);
				exit(EXIT_FAILURE);
			}
		}
	}
	close(fd);
	return(EXIT_SUCCESS);
}

