#ifndef _HYDRA_MOD_H
#define _HYDRA_MOD_H

#ifdef NESSUS_PLUGIN
 #include <includes.h>
#endif

#include "hydra.h"

extern void hydra_child_exit();
extern void  hydra_register_socket(int s);
extern char *hydra_get_next_pair();
extern char *hydra_get_next_login();
extern char *hydra_get_next_password();
extern void  hydra_completed_pair();
extern void  hydra_completed_pair_found();
extern void  hydra_report_found(int port, char * svc, FILE *fp);
extern int   hydra_connect_ssl(unsigned long int host, int port);
extern int   hydra_connect_tcp(unsigned long int host, int port);
extern int   hydra_connect_udp(unsigned long int host, int port);
extern int   hydra_disconnect(int socket);
extern int   hydra_data_ready(int socket);
extern int   hydra_recv(int socket, char *buf, int length);
extern char *hydra_receive_line(int socket);
extern int   hydra_send(int socket, char *buf, int size, int options);
extern int   make_to_lower(char *buf);

int debug;
int verbose;
int waittime;
int port;

#endif
