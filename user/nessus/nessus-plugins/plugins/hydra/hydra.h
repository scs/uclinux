#ifndef _HYDRA_H

#ifndef NESSUS_PLUGIN
 #include <stdio.h>
 #include <string.h>
 #include <unistd.h>
 #include <stdlib.h>
 #include <signal.h>
 #include <string.h>
 #include <strings.h>
 #include <time.h>
 #include <sys/time.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netdb.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <fcntl.h>
 #include <ctype.h>
 #include <sys/resource.h>
 #include <sys/wait.h>
#endif

#ifdef HAVE_OPENSSL
 #define HYDRA_SSL
#endif
#ifdef HAVE_SSL
 #ifndef HYDRA_SSL
  #define HYDRA_SSL
 #endif
#endif

#define OPTION_SSL 1

#define PORT_FTP	21
#define PORT_FTP_SSL	990
#define PORT_TELNET	23
#define PORT_TELNET_SSL	992
#define PORT_HTTP	80
#define PORT_HTTP_SSL	443
#define PORT_POP3	110
#define PORT_POP3_SSL	995
#define PORT_NNTP	119
#define PORT_NNTP_SSL	563
#define PORT_SMB	139
#define PORT_SMB_SSL    139
#define PORT_IMAP	143
#define PORT_IMAP_SSL	993
#define PORT_LDAP	389
#define PORT_LDAP_SSL   636
#define PORT_REXEC	512
#define PORT_REXEC_SSL	512
#define PORT_SOCKS5     1080
#define PORT_SOCKS5_SSL 1080
#define PORT_ICQ	4000
#define PORT_ICQ_SSL	-1
#define PORT_VNC	5900
#define PORT_VNC_SSL	5901
#define PORT_PCNFS	0
#define PORT_PCNFS_SSL	-1

#define _HYDRA_H
#endif
