#ifndef NMAP_H
#define NMAP_H

/************************INCLUDES**********************************/


/************************DEFINES************************************/

/* Default number of ports in paralell.  Doesn't always involve actual 
   sockets.  Can also adjust with the -M command line option.  */
#define MAX_SOCKETS 24
#define MAX_SOCKETS_ALLOWED MAX_SOCKETS



/***********************STRUCTURES**********************************/

typedef struct port {
  unsigned short portno;
  unsigned char proto;
  char *owner;
  struct port *next;
} port;

typedef port *portlist;

/***********************PROTOTYPES**********************************/


/* our scanning functions */
portlist tcp_scan(struct arglist *, struct in_addr *, unsigned short *, 
		  portlist *, struct arglist *, struct arglist *);

unsigned short *getpts(char *, int* ); /* someone stole the name getports()! */

extern int nmap_main(struct arglist *, struct arglist *, char *);
/* socket manipulation functions */
void init_socket(int );
int unblock_socket(int );
int block_socket(int );
#endif /* NMAP_H */
