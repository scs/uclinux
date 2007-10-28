/*      $Id: lircrcd.c,v 5.3 2006/05/06 09:40:07 lirc Exp $      */

/****************************************************************************
 ** lircrcd.c ***************************************************************
 ****************************************************************************
 *
 * lircrcd - daemon that manages current mode for all applications
 *
 * Copyright (C) 2004 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <getopt.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

#include "lirc_client.h"

#define MAX_CLIENTS 100
#define PACKET_SIZE (256)
#define WHITE_SPACE " \t"

struct config_info
{
	char *config_string;
	struct config_info *next;
};

struct event_info
{
	char *code;
	struct config_info *first;
	struct event_info *next;
};

struct client_data
{
	int fd;
	char *ident_string;
	struct event_info *first_event;
	char *pending_code;
};

struct protocol_directive
{
	char *name;
	int (*function)(int fd,char *message,char *arguments);
};

static int code_func(int fd,char *message,char *arguments);
static int ident_func(int fd,char *message,char *arguments);
static int getmode_func(int fd,char *message,char *arguments);
static int setmode_func(int fd,char *message,char *arguments);
static int send_result(int fd, char *message, const char *result);
static int send_success(int fd,char *message);

struct protocol_directive directives[] =
{
	{"CODE",code_func},
	{"IDENT",ident_func},
	{"GETMODE",getmode_func},
	{"SETMODE",setmode_func},
	{NULL,NULL}
	/*
	{"DEBUG",debug},
	{"DEBUG_LEVEL",debug_level},
	*/
};

enum protocol_string_num {
	P_BEGIN=0,
	P_DATA,
	P_END,
	P_ERROR,
	P_SUCCESS,
	P_SIGHUP
};

char *protocol_string[] = 
{
	"BEGIN\n",
	"DATA\n",
	"END\n",
	"ERROR\n",
	"SUCCESS\n",
	"SIGHUP\n"
};

static int debug;

#ifdef DEBUG
#define LOGPRINTF(level,fmt,args...)	\
  if(level<=debug) logprintf(LOG_DEBUG,fmt, ## args )
#define LOGPERROR(level,s) \
  if(level<=debug) logperror(LOG_DEBUG,s)
#else
#define LOGPRINTF(level,fmt,args...)	\
  do {} while(0)
#define LOGPERROR(level,s) \
  do {} while(0)
#endif

#define logprintf syslog
#define logperror(prio,s) if((s)!=NULL) syslog(prio,"%s: %m\n",(char *) s); else syslog(prio,"%m\n")

const char *progname="lircrcd";

static sig_atomic_t term=0;
static int termsig;
static int clin=0;
static struct client_data clis[MAX_CLIENTS];

static struct lirc_config *config;

static int send_error(int fd,char *message,char *format_str, ...);
static int handle_input();

static inline int max(int a,int b)
{
	return(a>b ? a:b);
}

static int get_client_index(int fd)
{
	int i;
	
	for(i=0; i<clin; i++)
	{
		if(fd == clis[i].fd)
		{
			return i;
		}
	}
	/* shouldn't ever happen */
	return -1;
}

/* cut'n'paste from fileutils-3.16: */

#define isodigit(c) ((c) >= '0' && (c) <= '7')

/* Return a positive integer containing the value of the ASCII
   octal number S.  If S is not an octal number, return -1.  */

static int
oatoi (s)
     char *s;
{
  register int i;

  if (*s == 0)
    return -1;
  for (i = 0; isodigit (*s); ++s)
    i = i * 8 + *s - '0';
  if (*s)
    return -1;
  return i;
}

/* A safer write(), since sockets might not write all but only some of the
   bytes requested */

inline int write_socket(int fd, char *buf, int len)
{
	int done,todo=len;

	while(todo)
	{
		done=write(fd,buf,todo);
		if(done<=0) return(done);
		buf+=done;
		todo-=done;
	}
	return(len);
}

inline int write_socket_len(int fd, char *buf)
{
	int len;

	len=strlen(buf);
	if(write_socket(fd,buf,len)<len) return(0);
	return(1);
}

inline int read_timeout(int fd,char *buf,int len,int timeout)
{
	fd_set fds;
	struct timeval tv;
	int ret,n;
	
	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	tv.tv_sec=timeout;
	tv.tv_usec=0;
	
	/* CAVEAT: (from libc documentation)
     Any signal will cause `select' to return immediately.  So if your
     program uses signals, you can't rely on `select' to keep waiting
     for the full time specified.  If you want to be sure of waiting
     for a particular amount of time, you must check for `EINTR' and
     repeat the `select' with a newly calculated timeout based on the
     current time.  See the example below.

     Obviously the timeout is not recalculated in the example because
     this is done automatically on Linux systems...
	*/
     
	do
	{
		ret=select(fd+1,&fds,NULL,NULL,&tv);
	}
	while(ret==-1 && errno==EINTR);
	if(ret==-1)
	{
		logprintf(LOG_ERR,"select() failed");
		logperror(LOG_ERR,NULL);
		return(-1);
	}
	else if(ret==0) return(0); /* timeout */
	n=read(fd,buf,len);
	if(n==-1)
	{
		logprintf(LOG_ERR,"read() failed");
		logperror(LOG_ERR,NULL);
		return(-1);
	}
	return(n);
}

static void sigterm(int sig)
{
	/* all signals are blocked now */
	if(term) return;
	term=1;
	termsig=sig;
}

static void nolinger(int sock)
{
	static struct linger  linger = {0, 0};
	int lsize  = sizeof(struct linger);
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger, lsize);
}

static void free_config_info(struct config_info *ci)
{
	struct config_info *next;
	
	while(ci != NULL)
	{
		if(ci->config_string != NULL) free(ci->config_string);
		
		next = ci->next;
		free(ci);
		ci = next;
	}
}

static void free_event_info(struct event_info *ei)
{
	struct event_info *next;
	
	while(ei != NULL)
	{
		if(ei->code != NULL) free(ei->code);
		
		free_config_info(ei->first);
		
		next = ei->next;
		free(ei);
		ei = next;
	}
}

static void remove_client(int i)
{
	shutdown(clis[i].fd,2);
	close(clis[i].fd);
	if(clis[i].ident_string) free(clis[i].ident_string);
	if(clis[i].pending_code) free(clis[i].pending_code);
	free_event_info(clis[i].first_event);
	
	LOGPRINTF(1, "removed client");
	
	clin--;
	for(;i<clin;i++)
	{
		clis[i]=clis[i+1];
	}
}

void add_client(int sock)
{
	int fd;
	socklen_t clilen;
	struct sockaddr client_addr;
	int flags;

	clilen=sizeof(client_addr);
	fd=accept(sock,(struct sockaddr *)&client_addr,&clilen);
	if(fd==-1) 
	{
		logprintf(LOG_ERR,"accept() failed for new client");
		logperror(LOG_ERR,NULL);
		return;
	};

	if(fd>=FD_SETSIZE || clin>=MAX_CLIENTS)
	{
		logprintf(LOG_ERR,"connection rejected");
		shutdown(fd,2);
		close(fd);
		return;
	}
	nolinger(fd);
	flags=fcntl(fd,F_GETFL,0);
	if(flags!=-1)
	{
		fcntl(fd,F_SETFL,flags|O_NONBLOCK);
	}
	LOGPRINTF(1, "accepted new client");
	clis[clin].fd=fd;
	clis[clin].ident_string = NULL;
	clis[clin].first_event = NULL;
	clis[clin].pending_code = NULL;
	clin++;
}

static int opensocket(const char *configfile, const char *socketname,
		      mode_t permission, struct sockaddr_un *addr)
{
	int sockfd;
	struct stat s;
	int new=1;
	int ret;
	
	/* get socket name */
	if((socketname==NULL &&
	    lirc_getsocketname(configfile,
			       addr->sun_path, sizeof(addr->sun_path)) > 
	    sizeof(addr->sun_path)) ||
	   (socketname!=NULL &&
	    strlen(socketname)>=sizeof(addr->sun_path)))
	{
		fprintf(stderr, "%s: filename too long", progname);
		return -1;
	}
	if(socketname!=NULL)
	{
		strcpy(addr->sun_path, socketname);
	}
	
	/* create socket*/
	sockfd=socket(AF_UNIX,SOCK_STREAM,0);
	if(sockfd==-1)
	{
		fprintf(stderr,"%s: could not create socket\n",progname);
		perror(progname);
		return -1;
	}
	
	/* 
	   get owner, permissions, etc.
	   so new socket can be the same since we
	   have to delete the old socket.  
	*/
	ret=stat(addr->sun_path, &s);
	if(ret==-1 && errno!=ENOENT)
	{
		fprintf(stderr,"%s: could not get file information for %s\n",
			progname, addr->sun_path);
		perror(progname);
		goto opensocket_failed;
	}
	
	if(ret!=-1)
	{
		new=0;
		ret=unlink(addr->sun_path);
		if(ret==-1)
		{
			fprintf(stderr,"%s: could not delete %s\n",
				progname, addr->sun_path);
			perror(progname);
			goto opensocket_failed;
		}
	}
	   
	addr->sun_family=AF_UNIX;
	if(bind(sockfd, (struct sockaddr *) addr, sizeof(*addr))==-1)
	{
		fprintf(stderr,"%s: could not assign address to socket\n",
			progname);
		perror(progname);
		goto opensocket_failed;
	}
	
	if(new ?
	   chmod(addr->sun_path, permission):
	   (chmod(addr->sun_path, s.st_mode)==-1 ||
	    chown(addr->sun_path, s.st_uid, s.st_gid)==-1)
	   )
	{
		fprintf(stderr,"%s: could not set file permissions\n",
			progname);
		perror(progname);
		goto opensocket_failed;
	}
	   
	listen(sockfd,3);
	nolinger(sockfd);

	return sockfd;
	
 opensocket_failed:
	close(sockfd);
	return -1;
}

static int code_func(int fd,char *message,char *arguments)
{
	int index;
	struct event_info *ei;
	struct config_info *ci;
	int ret;
	
	index = get_client_index(fd);
	if(index == -1)
	{
		return send_error(fd, message, "identify yourself first!\n");
	}
	if(clis[index].pending_code != NULL)
	{
		return send_error(fd, message, "protocol error\n");
	}
	
	LOGPRINTF(3, "%s asking for code -%s-",
		  clis[index].ident_string, arguments);
	
	ei = clis[index].first_event;
	if(ei != NULL)
	{
		LOGPRINTF(3, "compare: -%s- -%s-", ei->code, arguments);
		if(strcmp(ei->code, arguments) == 0)
		{
			
			ci = ei->first;
			if(ci != NULL)
			{
				LOGPRINTF(3, "result: -%s-",
					  ci->config_string);
				ret = send_result(fd, message,
						  ci->config_string);
				ei->first = ci->next;
				free(ci->config_string);
				free(ci);
				return ret;
			}
			else
			{
				clis[index].first_event = ei->next;
				free(ei->code);
				free(ei);
				return send_success(fd, message);
			}
		}
		else
		{
			return send_success(fd, message);
		}
	}
	
	clis[index].pending_code = strdup(arguments);
	if(clis[index].pending_code == NULL)
	{
		return send_error(fd, message, "out of memory\n");
	}
	return 1;
}

static int ident_func(int fd,char *message,char *arguments)
{
	int index;
	
	if(arguments == NULL)
	{
		return send_error(fd, message, "protocol error\n");
	}
	LOGPRINTF(2, "IDENT %s", arguments);
	index = get_client_index(fd);
	if(clis[index].ident_string != NULL)
	{
		return send_error(fd, message, "protocol error\n");
	}
	clis[index].ident_string = strdup(arguments);
	if(clis[index].ident_string == NULL)
	{
		return send_error(fd, message, "out of memory\n");
	}
	
	LOGPRINTF(1, "%s connected", clis[index].ident_string);
	return(send_success(fd,message));
}

static int getmode_func(int fd,char *message,char *arguments)
{
	if(arguments != NULL)
	{
		return send_error(fd, message, "protocol error\n");
	}
	LOGPRINTF(2, "GETMODE");
	if(lirc_getmode(config))
	{
		return send_result(fd, message, lirc_getmode(config));
	}
	return(send_success(fd,message));
}

static int setmode_func(int fd,char *message,char *arguments)
{
	const char *mode = NULL;
	
	LOGPRINTF(2, arguments!=NULL ? "SETMODE %s":"SETMODE", arguments);
	if((mode = lirc_setmode(config, arguments)))
	{
		return send_result(fd, message, mode);
	}
	return arguments==NULL ?
		send_success(fd,message):
		send_error(fd, message, "out of memory\n");
}

static int send_result(int fd, char *message, const char *result)
{
	char *count = "1\n";
	char buffer[strlen(result)+1+1];
	
	sprintf(buffer, "%s\n", result);
	
	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]) &&
	     write_socket_len(fd,protocol_string[P_DATA]) &&
	     write_socket_len(fd,count) &&
	     write_socket_len(fd,buffer) &&
	     write_socket_len(fd,protocol_string[P_END]))) return(0);
	return(1);
}

static int send_success(int fd,char *message)
{
	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]) &&
	     write_socket_len(fd,protocol_string[P_END]))) return(0);
	return(1);
}

static int send_error(int fd,char *message,char *format_str, ...)
{
	char lines[4],buffer[PACKET_SIZE+1];
	int i,n,len;
	va_list ap;  
	char *s1,*s2;
	
	va_start(ap,format_str);
	vsprintf(buffer,format_str,ap);
	va_end(ap);
	
	s1=strrchr(message,'\n');
	s2=strrchr(buffer,'\n');
	if(s1!=NULL) s1[0]=0;
	if(s2!=NULL) s2[0]=0;
	logprintf(LOG_ERR,"error processing command: %s",message);
	logprintf(LOG_ERR,"%s",buffer);
	if(s1!=NULL) s1[0]='\n';
	if(s2!=NULL) s2[0]='\n';

	n=0;
	len=strlen(buffer);
	for(i=0;i<len;i++) if(buffer[i]=='\n') n++;
	sprintf(lines,"%d\n",n);
	
	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_ERROR]) &&
	     write_socket_len(fd,protocol_string[P_DATA]) &&
	     write_socket_len(fd,lines) &&
	     write_socket_len(fd,buffer) &&
	     write_socket_len(fd,protocol_string[P_END]))) return(0);
	return(1);
}

static int get_command(int fd)
{
	int length;
	char buffer[PACKET_SIZE+1],backup[PACKET_SIZE+1];
	char *end;
	int packet_length,i;
	char *directive;

	length=read_timeout(fd,buffer,PACKET_SIZE,0);
	packet_length=0;
	while(length>packet_length)
	{
		buffer[length]=0;
		end=strchr(buffer,'\n');
		if(end==NULL)
		{
			logprintf(LOG_ERR,"bad send packet: \"%s\"",buffer);
			/* remove clients that behave badly */
			return(0);
		}
		end[0]=0;
		LOGPRINTF(1,"received command: \"%s\"",buffer);
		packet_length=strlen(buffer)+1;

		strcpy(backup,buffer);strcat(backup,"\n");
		directive=strtok(buffer,WHITE_SPACE);
		if(directive==NULL)
		{
			if(!send_error(fd,backup,"bad send packet\n"))
				return(0);
			goto skip;
		}
		for(i=0;directives[i].name!=NULL;i++)
		{
			if(strcasecmp(directive,directives[i].name)==0)
			{
				if(!directives[i].
				   function(fd,backup,strtok(NULL,"")))
					return(0);
				goto skip;
			}
		}
		
		if(!send_error(fd,backup,"unknown directive: \"%s\"\n",
			       directive))
			return(0);
	skip:
		if(length>packet_length)
		{
			int new_length;

			memmove(buffer,buffer+packet_length,
				length-packet_length+1);
			if(strchr(buffer,'\n')==NULL)
			{
				new_length=read_timeout(fd,buffer+length-
							packet_length,
							PACKET_SIZE-
							(length-
							 packet_length),5);
				if(new_length>0)
				{
					length=length-packet_length+new_length;
				}
				else
				{
					length=new_length;
				}
			}
			else
			{
				length-=packet_length;
			}
			packet_length=0;
		}
	}

	if(length==0) /* EOF: connection closed by client */
	{
		return(0);
	}
	return(1);
}

static void loop(int sockfd, int lircdfd)
{
	fd_set fds;
	int maxfd,i;
	int ret;

	while(1)
	{
		do{
			/* handle signals */
			if(term)
			{
				logprintf(LOG_NOTICE,"caught signal");
				return;
			}
			FD_ZERO(&fds);
			FD_SET(sockfd,&fds);
			FD_SET(lircdfd,&fds);
			maxfd=max(sockfd, lircdfd);

			for(i=0;i<clin;i++)
			{
				FD_SET(clis[i].fd,&fds);
				maxfd=max(maxfd,clis[i].fd);
			}
			LOGPRINTF(3, "select");
			ret=select(maxfd+1,&fds,NULL,NULL,NULL);
			
			if(ret==-1 && errno!=EINTR)
			{
				logprintf(LOG_ERR,"select() failed");
				logperror(LOG_ERR,NULL);
				raise(SIGTERM);
				continue;
			}
		}
		while(ret==-1 && errno==EINTR);
		
		for(i=0;i<clin;i++)
		{
			if(FD_ISSET(clis[i].fd,&fds))
			{
				FD_CLR(clis[i].fd,&fds);
				if(get_command(clis[i].fd)==0)
				{
					remove_client(i);
					i--;
					if(clin == 0)
					{
						logprintf(LOG_INFO, "last client disconnected, shutting down");
						return;
					}
				}
			}
		}
		if(FD_ISSET(sockfd,&fds))
		{
			LOGPRINTF(1,"registering local client");
			add_client(sockfd);
		}
		if(FD_ISSET(lircdfd,&fds))
		{
			if(!handle_input())
			{
				while(clin>0)
				{
					remove_client(0);
				}
				logprintf(LOG_ERR, "connection lost");
				return;
			}
		}
	}
}

static int schedule(int index, char *config_string)
{
	struct event_info *e;
	struct config_info *c, *n;
	LOGPRINTF(2, "schedule(%s): -%s-",
		  clis[index].ident_string, config_string);
	
	e = clis[index].first_event;
	while(e->next) e = e->next;
	
	c = e->first;
	while(c && c->next) c = c->next;
	
	n = malloc(sizeof(*c));
	
	if(n == NULL)
	{
		return 0;
	}
	
	n->config_string = strdup(config_string);
	
	if(n->config_string == NULL)
	{
		free(n);
		return 0;
	}
	n->next = NULL;
	
	if(c == NULL)
	{
		e->first = n;
	}
	else
	{
		c->next = n;
	}
	return 1;
}

static int handle_input()
{
	char *code;
	char *config_string;
	char *prog;
	int ret;
	struct event_info *e, *n;
	int i;
	
	LOGPRINTF(1,"input from lircd");
	if(lirc_nextcode(&code) != 0)
	{
		return 0;
	}
	
	for(i=0; i<clin; i++)
	{
		n = malloc(sizeof(*n));
		
		if(n == NULL)
		{
			return 0;
		}
		
		n->code = strdup(code);

		if(n->code == NULL)
		{
			free(n);
			return 0;
		}
		
		/* remove trailing \n */
		n->code[strlen(n->code)-1] = 0;
		
		n->first = NULL;
		n->next = NULL;
		
		e = clis[i].first_event;
		while(e && e->next) e = e->next;
		
		if(e == NULL)
		{
			clis[i].first_event = n;
		}
		else
		{
			e->next = n;
		}
	}
	LOGPRINTF(3, "input from lircd: \"%s\"", code);
	while((ret=lirc_code2charprog(config, code, &config_string, &prog))==0 &&
	      config_string!=NULL)
	{
		int i;
		
		LOGPRINTF(3, "%s: -%s-", prog, config_string);
		for(i=0; i<clin; i++)
		{
			if(strcmp(prog, clis[i].ident_string) == 0)
			{
				if(!schedule(i, config_string))
				{
					return 0;
				}
			}
		}
	}
	for(i=0; i<clin; i++)
	{
		if(clis[i].pending_code != NULL)
		{
			char message[strlen(clis[i].pending_code)+1];
			char *backup;
			
			LOGPRINTF(3, "pending_code(%s): -%s-",
				  clis[i].ident_string, clis[i].pending_code);
			backup = clis[i].pending_code;
			clis[i].pending_code = NULL;
			
			sprintf(message, "CODE %s\n", backup);
			(void) code_func(clis[i].fd, message, backup);
			free(backup);
		}
	}
	free(code);
	
	return 1;
}

int main(int argc, char **argv)
{
	char *configfile;
	const char *socketfile = NULL;
	mode_t permission=S_IRUSR|S_IWUSR;
	int socket;
	int lircdfd;
	struct sigaction act;
	struct sockaddr_un addr;
	char dir[FILENAME_MAX+1] = { 0 };
	
	debug = 0;
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"permission",required_argument,NULL,'p'},
                        {"output",required_argument,NULL,'o'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvp:o:",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options] config-file\n",progname);
			printf("\t -h --help\t\t\tdisplay this message\n");
			printf("\t -v --version\t\t\tdisplay version\n");
			printf("\t -p --permission=mode\t\tfile permissions for socket\n");
                        printf("\t -o --output=socket\t\toutput socket filename\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s %s\n",progname,VERSION);
			return(EXIT_SUCCESS);
		case 'p':
			if(oatoi(optarg)==-1)
			{
				fprintf(stderr,"%s: invalid mode\n",progname);
				return(EXIT_FAILURE);
			}
			permission=oatoi(optarg);
			break;
                case 'o':
                        socketfile=optarg;
                        break;
		default:
			printf("Usage: %s [options] config-file\n",progname);
			return(EXIT_FAILURE);
		}
	}
	if(optind==argc-1)
	{
	        configfile=argv[optind];
	}
	else
	{
		fprintf(stderr,"%s: invalid argument count\n",progname);
		return EXIT_FAILURE;
	}
	
	lircdfd=lirc_init("lircrcd", 0);
	if(lircdfd == -1)
	{
		return EXIT_FAILURE;
	}
	
	/* read config file */
	if(lirc_readconfig_only(configfile,&config,NULL)!=0)
	{
		lirc_deinit();
		return EXIT_FAILURE;
	}
	
	/* open socket */
	socket=opensocket(configfile, socketfile, permission, &addr);
	if(socket==-1)
	{
		lirc_freeconfig(config);
		lirc_deinit();
		return EXIT_FAILURE;
	}
	
	/* fork */
	getcwd(dir, sizeof(dir));
#ifdef DAEMONIZE
	if(daemon(0,0)==-1)
	{
		fprintf(stderr, "%s: daemon() failed\n", progname);
		perror(progname);
		shutdown(socket, 2);
		close(socket);
		lirc_freeconfig(config);
		return -1;
	}
#endif

	openlog(progname, LOG_CONS|LOG_PID, LOG_USER);
	umask(0);
	signal(SIGPIPE,SIG_IGN);
	
	act.sa_handler=sigterm;
	sigfillset(&act.sa_mask);
	act.sa_flags=SA_RESTART;           /* don't fiddle with EINTR */
	sigaction(SIGTERM,&act,NULL);
	sigaction(SIGINT,&act,NULL);
	sigaction(SIGHUP,&act,NULL);
	
	logprintf(LOG_NOTICE, "%s started", progname);
	loop(socket, lircdfd);
	
	closelog();
	shutdown(socket, 2);
	close(socket);
	if(chdir(dir) == 0) unlink(addr.sun_path);
	lirc_freeconfig(config);
	lirc_deinit();
	return EXIT_SUCCESS;
}
