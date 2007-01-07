/*
 * nmap_tcp_connect plugin
 *
 * This code is mostly (c) Fyodor <fyodor@dhp.com>. Several changes
 * have been made by Renaud Deraison <deraison@worldnet.fr>.
 *
 * This plugin is distributed under the GPL
 *
 */

#include <includes.h>
#include <stdarg.h>
#include "nmap.h"



#define EN_NAME "tcp connect() scan"
#define FR_NAME "tcp connect()"

#define EN_DESC "\
This is the Nmap TCP connect() scan.\n\n\
This scan technique is very fast and\n\
reliable against non-firewalled hosts.\n\n\
More information about Nmap :\n\
http://www.insecure.org/nmap\n\n\
Risk factor : None"

#define FR_DESC "\
Ce plugin est le TCP connect() scan de Nmap.\n\n\
Cette technique de scan est rapide et fiable\n\
contre des machines non protégée par firewall.\n\n\
Pour plus d'informations sur Nmap, allez sur :\n\
http://www.insecure.org/nmap\n\n\
Facteur de risque : Aucun"


#define COPYRIGHT "Copyright (C) Fyodor - <fyodor@dhp.com>"

#define EN_SUMMARY "Performs a noisy TCP scan"
#define FR_SUMMARY "Fait un scan TCP bruyant"

#define EN_FAMILY "Port scanners"
#define FR_FAMILY "Scanners de ports"

PlugExport int plugin_init(struct arglist * desc)
{
 plug_set_id(desc, 10335);
 plug_set_version(desc, "$Revision: 1.18 $");
   
         
 plug_set_name(desc, FR_NAME, "francais");
 plug_set_name(desc, EN_NAME, NULL);
 
 
 plug_set_summary(desc, FR_SUMMARY, "francais");
 plug_set_summary(desc, EN_SUMMARY, NULL);
 
 
 plug_set_description(desc, FR_DESC, "francais");
 plug_set_description(desc, EN_DESC, NULL);
 
 plug_set_copyright(desc, COPYRIGHT,NULL);
 plug_set_category(desc, ACT_SCANNER);
 plug_set_family(desc, FR_FAMILY, "francais");
 plug_set_family(desc, EN_FAMILY, NULL);
 
 plug_set_dep(desc, "ping_host.nasl");
 return(0);
}



PlugExport int plugin_run(struct arglist * env)
{
  unsigned short *ports;

  struct arglist * globals = arg_get_value(env, "globals");
  struct arglist * preferences = arg_get_value(env, "preferences");
  struct arglist * hostinfos = arg_get_value(env, "HOSTNAME");
  char * port_range = arg_get_value(preferences, "port_range");
  portlist openports = NULL;
  struct in_addr *p_addr;
  int num;
  
  ports = getpts(port_range, &num);
  p_addr = arg_get_value(hostinfos, "IP");
  if( p_addr == NULL )
  	return -1;
  tcp_scan(globals, p_addr, ports, &openports, env, hostinfos);
  plug_set_key(env, "Host/scanned", ARG_INT, (void*)1);
  comm_send_status(globals, arg_get_value(hostinfos, "NAME"),"portscan", num, num);
  return 0;
}


void init_socket(int sd) {
struct linger l;

l.l_onoff = 1;
l.l_linger = 0;

if (setsockopt(sd, SOL_SOCKET, SO_LINGER,  (void *) &l, sizeof(struct linger)))
  {
   fprintf(stderr, "Problem setting socket SO_LINGER, errno: %d\n", errno);
   perror("setsockopt");
  }
}



int block_socket(int sd) {
int options;
options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
return 1;
}


int unblock_socket(int sd) {
int options;
/*Unblock our socket to prevent recvfrom from blocking forever
  on certain target ports. */
options = O_NONBLOCK | fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
return 1;
}





portlist tcp_scan(globals, target,portarray, ports,env, hostdata) 
     struct arglist * globals;
     struct in_addr *target;
     unsigned short *portarray;
     portlist *ports;
     struct arglist * env;
     struct arglist * hostdata;	
{
int starttime, current_out = 0, res , deadindex = 0, i=0, j=0, k=0, max=0; 
struct sockaddr_in sock, stranger;
int sockaddr_in_len = sizeof(struct sockaddr_in);
int seconds, seconds2;  /* Store time temporarily for timeout purposes */
int *sockets;   /* All socket descriptors */
int *deadstack; /* Stack of dead descriptors (indexes to sockets[] */
unsigned short *portno;  /* port numbers of sd's, parallel to sockets[] */
int *times; /* initial connect() times of sd's, parallel to sockets[].  For timeout information. */
int *retrystack; /* sd's that need to be retried */
int *retries; /* nr. or retries for this port */
int retryindex = -1;
int numretries = 2; /* How many retries before we give up on a connection */
char *owner, *buf; 
int timeout = 10;
int current_socket = -1;
fd_set *fds_read = malloc(sizeof(fd_set)), *fds_write = malloc(sizeof(fd_set));
struct timeval *nowait = malloc(sizeof(struct timeval)),  
		*longwait = malloc(sizeof(struct timeval)); 
int timeouts=0;
int num_scanned = 0;
int end_port = 0;
j = 0;
while(portarray[j++])end_port++;
j = 0;

nowait->tv_sec = nowait->tv_usec = 0;
longwait->tv_sec = 7 ; longwait->tv_usec = 0;
sockets = emalloc(sizeof(int)*(MAX_SOCKETS_ALLOWED+1));
deadstack = emalloc(sizeof(int)*(MAX_SOCKETS_ALLOWED+1));
portno = emalloc(sizeof(unsigned short)*(MAX_SOCKETS_ALLOWED+1));
times = emalloc(sizeof(int)*(MAX_SOCKETS_ALLOWED+1));
retrystack = emalloc(sizeof(int)*(MAX_SOCKETS_ALLOWED+1));
retries = emalloc(sizeof(int)*65536);
owner = emalloc(513);
buf = emalloc(65536);
signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our 'write 0 bytes' test
			     doesn't crash our program!*/
owner[0] = '\0';
starttime = time(NULL);
bzero((char *)&sock,sizeof(struct sockaddr_in));
sock.sin_addr.s_addr = target->s_addr;
sock.sin_family=AF_INET;
FD_ZERO(fds_read);
FD_ZERO(fds_write);
comm_send_status(globals, arg_get_value(hostdata, "NAME"),"portscan",  0,end_port);

/* Initially, all of our sockets are "dead" */
for(i = 0 ; i < MAX_SOCKETS_ALLOWED; i++) {
  deadstack[deadindex++] = i;
  portno[i] = 0;
}

deadindex--; 
/* deadindex always points to the most recently added dead socket index */

while(portarray[j] || retryindex >= 0 || current_out != 0) {
  longwait->tv_sec = timeout;
  longwait->tv_usec = nowait->tv_sec = nowait->tv_usec = 0;
  seconds = time(NULL);
  for(i=current_out; i < MAX_SOCKETS_ALLOWED && (portarray[j] || retryindex >= 0); i++,
  	num_scanned++) {
  	if(num_scanned==100){
	comm_send_status(globals, arg_get_value(hostdata, "NAME"), 
        "portscan",
	portarray[j]>0?portarray[j]-1:0, end_port);
        num_scanned = 0;
        }      
    current_socket = deadstack[deadindex--];
    if ((sockets[current_socket] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
      {perror("Socket troubles"); return(NULL);}
    if (sockets[current_socket] > max) max = sockets[current_socket]; 
    set_socket_source_addr( sockets[current_socket], 0);
    current_out++;
    unblock_socket(sockets[current_socket]);
    init_socket(sockets[current_socket]);
    if (retryindex < 0) {
      portno[current_socket] = portarray[j++];
    }
    else { /* we have retries to do ...*/
      portno[current_socket] = retrystack[retryindex--];
    }
    sock.sin_port = htons(portno[current_socket]);
    times[current_socket] = seconds;
    if ((res = connect(sockets[current_socket],(struct sockaddr *)&sock,sizeof(struct sockaddr)))!=-1) 
    {
      scanner_add_port(env, portno[current_socket], "tcp");
  
      if (max == sockets[current_socket])
	max--;
      FD_CLR(sockets[current_socket], fds_read);
      FD_CLR(sockets[current_socket], fds_write);
      deadstack[++deadindex] = current_socket;
      current_out--;
      portno[current_socket] = 0;
      close(sockets[current_socket]);
    }
    else {  /* Connect() failed, normal case */
      switch(errno) {
      case EINPROGRESS: /* The one I always see */
      case EAGAIN:
	block_socket(sockets[current_socket]); 
	FD_SET(sockets[current_socket], fds_write);
	FD_SET(sockets[current_socket], fds_read);
	break;
      default:
      case ECONNREFUSED:
	if (max == sockets[current_socket]) max--;
	deadstack[++deadindex] = current_socket;
	current_out--;
	portno[current_socket] = 0;
	close(sockets[current_socket]);
	timeouts = 0; /* We may not want to give up on this host */
	break;
      }
    }
  }
   if (!portarray[j] && retryindex < 0) sleep(2); /*If we are done, wait a second for any last packets*/
  while((res = select(max + 1, fds_read, fds_write, NULL, 
		      (current_out < MAX_SOCKETS_ALLOWED)?
		      nowait : longwait)) > 0) {
    for(k=0; k < MAX_SOCKETS_ALLOWED; k++)
      if (portno[k]) {
	if (FD_ISSET(sockets[k], fds_write)
	    && FD_ISSET(sockets[k], fds_read)) {
	  /* printf("Socket at port %hi is selectable for r & w.", portno[k]); */
	  res = recvfrom(sockets[k], buf, 65536, 0, (struct sockaddr *)
			 & stranger, &sockaddr_in_len);
	  if (res >= 0) { 
           scanner_add_port(env, portno[k], "tcp");
			
	  }
	  if (max == sockets[k])
	    max--;
	  FD_CLR(sockets[k], fds_read);
	  FD_CLR(sockets[k], fds_write);
	  deadstack[++deadindex] = k;
	  current_out--;
	  portno[k] = 0;
	  close(sockets[k]);
	}
	else if(FD_ISSET(sockets[k], fds_write)) {
	   /* printf("Socket at port %hi is selectable for w only.VERIFYING\n",
	    portno[k]); */
	  res = send(sockets[k], buf, 0, 0);
	  if (res < 0 ) {
	    signal(SIGPIPE, SIG_IGN);
	  }
	  else {	    
        
	  scanner_add_port(env, portno[k], "tcp");
	   
	  }
	  if (max == sockets[k]) max--;
	  FD_CLR(sockets[k], fds_write);
	  deadstack[++deadindex] = k;
	  current_out--;
	  portno[k] = 0;
	  close(sockets[k]);
	}
	else if ( FD_ISSET(sockets[k], fds_read) ) {       
	  if (max == sockets[k]) max--;
	  FD_CLR(sockets[k], fds_read);
	  deadstack[++deadindex] = k;
	  current_out--;
	  portno[k] = 0;
	  close(sockets[k]);
	}
	else { /* neither read nor write selected */
	  if (time(NULL) - times[k] < 10) {
	 /* printf("Socket at port %hi not selecting, readding.\n",portno[k]); */
	  FD_SET(sockets[k], fds_write);
	  FD_SET(sockets[k], fds_read);
	  }
	  else { /* time elapsed */
	    if (retries[portno[k]] < numretries  && 
		(portarray[j] || retryindex >= 0)) {
	    /* don't readd if we are done with all other ports */ 
	      retries[portno[k]]++;
	      retrystack[++retryindex] = portno[k];
	    }
	    else {
	      timeouts++;	      
	    }	  	    
	    if (max == sockets[k]) max--;
	    FD_CLR(sockets[k], fds_write);
	    FD_CLR(sockets[k], fds_read);
	    deadstack[++deadindex] = k;
	    current_out--;
	    portno[k] = 0;
	    close(sockets[k]);
	  }
	}
      }
  longwait->tv_sec = timeout;
  longwait->tv_usec = 0;
  }
  /* If we can't send anymore packets (because full or out of ports) */
  if (current_out == MAX_SOCKETS_ALLOWED || (!portarray[j] && retryindex < 0)) {
    int z;
    seconds2 = time(NULL);
    for(z=0; z < MAX_SOCKETS_ALLOWED; z++) {
      if (portno[z] && seconds2 - times[z] >= 10) { /* Timed out, dr0p it */
	if (retries[portno[z]] < numretries && 
	    (portarray[j] || retryindex >= 0)) { /* don't re-add if we
						    are done with all other
						    ports */
	  retries[portno[z]]++;
	  retrystack[++retryindex] = portno[z];
	}
	else {
	  timeouts++;	      
	  if (max == sockets[z]) max--;
	  FD_CLR(sockets[z], fds_write);
	  FD_CLR(sockets[z], fds_read);
	  deadstack[++deadindex] = z;
	  current_out--;
	  portno[z] = 0;
	  close(sockets[z]);
	}
      }
    }
  }
}



for(k=0; k < MAX_SOCKETS_ALLOWED; k++) {
  if (portno[k]) {
   /* printf("Almost missed port %d\n", portno[k]); */
    close(sockets[k]);
  }
}

free(fds_read);
free(fds_write);
free(nowait);
free(longwait);
/*
free(sockets);
free(deadstack); 
free(portno); 
free(times);
free(retrystack); 
free(retries); 
free(owner);
free(buf);
*/
return NULL;
}
