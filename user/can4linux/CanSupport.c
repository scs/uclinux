#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include <can4linux.h>



int can_init(int port) {
  char dev[10];
  sprintf(dev,"/dev/can%d",port);
    
  return open(dev,O_RDWR);
}

int can_close(int fd) {
  return close(fd);
}

int can_send(int fd, int len,char *message) {
 char *token;
 canmsg_t tx;
 int j,sent=0;
 
 if(( token = strtok(message,":") ) != NULL ) {
   tx.flags=0;
   if( token[0] == 'r' || token[0] == 'R' ) {
     tx.flags = MSG_RTR;
     tx.id = strtol(&token[1],NULL,0);
     tx.length=len;
   } else {
     tx.id = strtol(token,NULL,0);
     j=0;
     while( (token = strtok(NULL,",")) != NULL ) {
       /*printf("'%c' ",strtol(token,NULL,0) );*/
       tx.data[j++] = strtol(token,NULL,0);
     }
     tx.length=(len>0 ? len : j );
   }
   sent = write(fd,&tx,1);
   /*if(sent > 0 ) printf(" OK\n"); fflush(stdout);*/
   
   return 1;
 } else {

   return -1;
 }

}


#if 0
int can_filter(int fd,char *fstring) {
  char *token;
  int i;
  if(( token = strtok(fstring,",")) != NULL ) {
    if( token[0] == '*' ) {
      can_Config(fd, CONF_FILTER, 0 ); 
 printf("\nfilter disabled");
    } else {
      can_Config(fd, CONF_FILTER, 1 );
      can_Config(fd, CONF_FENABLE, strtol(token,NULL,0));
printf("\naccept %d",strtol(token,NULL,0));
    }
    while((token=strtok(NULL,",")) != NULL ) {
      can_Config(fd, CONF_FENABLE, strtol(token,NULL,0));
printf("\naccept %d",strtol(token,NULL,0));
    }
    return 1;
  }
  return -1;
}  
#endif




char *can_read(int fd, int timeout) {
fd_set   rfds;
struct   timeval tv;
int      got,i,j;
canmsg_t rx[80];
static char databuf[4096];
char     *s;
char     type;

  FD_ZERO(&rfds);
  FD_SET(fd,&rfds);

  tv.tv_sec  = 0; /* wait 5 seconds before process terminates */
  tv.tv_usec = timeout;
  s = &databuf[0];
  /* s += sprintf(s,"",fd); */
  got=0;
  if( select(FD_SETSIZE, &rfds, NULL, NULL, ( timeout > 0 ? &tv : NULL )  ) > 0 && FD_ISSET(fd,&rfds) ) {

      got = read(fd, rx , 79 );
      /*s += sprintf(s, "got=%d",got);*/
      if( got > 0) {

	/*s += sprintf(s, "\n");*/

	for(i=0;i<got;i++) {
	  rx[i].data[rx[i].length] = 0;		/* why ???, you are overwriting something if length = 8 */
	  if(rx[i].flags & MSG_OVR) {
	    type = 'O';
	  } else if(rx[i].flags & MSG_EXT) {
	    type = 'e';
	  } else {
	    type = '.';
	  }
	  if( rx[i].flags & MSG_RTR ) {
	    s += sprintf(s, "%12lu.%06lu 0x%08lx R %c",
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id, type) ;
          }
	  else {
	    s += sprintf(s, "%12lu.%06lu 0x%08lx . %c %d ",
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id, type, rx[i].length );      
	    for(j=0;j<rx[i].length;j++)
	      s += sprintf(s, " 0x%02x",rx[i].data[j] ); 
	    for(;j<8;j++)
	      s += sprintf(s, "  .  "); 
	    s+=sprintf(s," '%s'",rx[i].data);
          }
	  s += sprintf(s, "\n");

	} 
      }
  }

return databuf;
}




