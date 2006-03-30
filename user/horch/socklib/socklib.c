/*
 * socklib - simple TCP socket interface
 *
 * Copyright (c) 2003 port GmbH Halle (Saale)
 *------------------------------------------------------------------
 * $Header$
 *
 *------------------------------------------------------------------
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.1  2006/03/30 15:40:48  hennerich
 * Apply horch user application patch/update form port GmbH
 *
 * Revision 1.4  2006/02/27 08:29:56  hae
 * use latest version of socklib
 *
 * Revision 1.10  2006/02/27 08:16:01  hae
 * fix type error
 * flush correct file descriptor
 *
 * Revision 1.9  2006/02/06 14:45:35  hae
 * allow to reuse the server port without waiting for the timeout
 * make use of the TCP_NODELAY socket option
 * this option can be specified with so_open2
 *
 * Revision 1.8  2005/06/17 10:06:42  hae
 * Compiler-Fehlermeldung entfernt
 *
 * Revision 1.7  2005/06/07 13:33:27  hae
 * Anpassung an CAN232 unter Linux
 *
 * Revision 1.6  2005/05/27 08:04:43  hae
 * Prüfung auf Null Zeiger
 * Debugausschriften kommentiert
 *
 * Revision 1.5  2004/12/08 16:27:16  hae
 * removed empty IPC ifdef
 * use write for Linux arm; not send
 *
 * Revision 1.4  2004/10/28 15:14:38  ro
 * so_server_doit() changed - timeout also for Linux
 * special for Linux: timeout == 0 means, no timeout
 * Linux timeout need for CPC driver, e.g. EtherCAN
 *
 * Revision 1.3  2003/10/21 12:08:51  boe
 * bearbeitete fd-Desc aus dem FD_ISSET  gelöscht
 *
 * Revision 1.2  2003/10/16 13:08:58  boe
 * use defines for return values at so_server_doit()
 * move client information to SOCKET_T
 * rename readline to so_readline
 *
 * Revision 1.1  2003/10/16 09:00:51  boe
 * socket library
 *
 *
 *
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#if defined( __WIN32__) || defined(_WIN32)
# ifndef __WIN32__
#  define __WIN32__
# endif
#  include <io.h>
#  include <sys/types.h>
#  include <winsock.h>
#  include <string.h>
#  include <errno.h>

#else
/* LINUX || CYGWIN */
#  include <unistd.h>                                            
#  include <errno.h>
#  include <signal.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <strings.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#endif


#define S_LIBRARY
#include "socklib.h"


int	so_debug   = 0;			/* enable/disable debugging */
static  SOCK_OPT_T sock_opt = {
	1	/* TCP_NODELAY - short reaction time, default on */
	};

/***************************************************************************
*
* so_open - open a socket stream
*
*
* \retval socket
*	a socket descriptor structure if succesful
* \retval NULL
*	if the socket can not be opened
*/

SOCKET_T *so_open(
	void
    )
{
SOCKET_T *sp;

#ifdef __WIN32__
  static WSADATA wd;

    /* initialize WinSock */
    if (WSAStartup(0x0101, &wd)) {
	fprintf(stderr, "cannot initialize WinSock\n");
	return NULL;
    }
    if (so_debug > 0) {
	printf("windows socket version: 0x%x\n", wd.wVersion);
    }
#endif

    /* get mem for socket structure */
    if ((sp = (SOCKET_T *)malloc(sizeof(SOCKET_T))) == 0) {
	return NULL;
    }

    /* call socket */
    sp->sd = socket(PF_INET, SOCK_STREAM, 0);
#ifdef __WIN32__
    if ( sp->sd == INVALID_SOCKET ) {
	perror("socket()");
	fprintf(stderr, "socket() - error %d\n", WSAGetLastError());
	WSACleanup();
	free(sp);
	return(NULL);
    }
#else
    if ( sp->sd < 0 ) {
# ifdef TARGET_IPC
	fprintf(stderr, "socket() open error %d\n", errno);
# else
	perror("socket()");
# endif
	free(sp);
	return(NULL);
    }
#endif

    sp->sinlen   = sizeof(sp->sin);
    sp->bindflag = S_RESET;

    sp->client = NULL;
    sp->actClients = 0;
    sp->maxClients = 0;

    return sp;
}

/***************************************************************************
*
* so_open2 - open a socket stream and set options
*
*
* \retval socket
*	a socket descriptor structure if succesful
* \retval NULL
*	if the socket can not be opened
*/
SOCKET_T *so_open2(
	SOCK_OPT_T socket_options
    )
{
    sock_opt = socket_options;

    return so_open();
}


/***************************************************************************
*
* so_close - close a socket stream
*
*
* \retval
*	the result of the close() call
*/

int so_close(
	SOCKET_T *sp		/* the socket descriptor from so_sopen() */
	)
{
int sd, i;

    if (sp == NULL)  {
        return 0;
    }

    /* close all connections from server */
    if (sp->client != NULL)  {
	for (i = 0; i < sp->maxClients; i++)  {
	    if (sp->client[i] != -1)  {
#ifdef __WIN32__
		closesocket(sp->client[i]);
#else /* __WIN32__ */
		close(sp->client[i]);
#endif /* __WIN32__ */
	    }
	}
    }

    sd = sp->sd;

#ifdef __WIN32__
    WSACleanup();
#endif

    free(sp);
    return(close(sd));
}


/***************************************************************************
*
* so_client - establish a client connection to a host
*
*
* \retval sd
*	the file descriptor of the socket
*/

int so_client(
	SOCKET_T *sp,		/* the socket descriptor from so_sopen() */
	char *host,		/* name of the host i should connect to */
	int port		/* port number of the service */
	)
{
struct hostent *hostent;

    if((hostent = gethostbyname(host)) == 0) {
	return -1;
    }

    sp->sin.sin_family      = (short)hostent->h_addrtype;
    sp->sin.sin_port        = htons((unsigned short)port);
    sp->sin.sin_addr.s_addr = *(unsigned long *)hostent->h_addr;

    if (connect(sp->sd, (struct sockaddr *)&sp->sin, sp->sinlen) ==  -1) {
	return -1;
    }

    return (sp->sd);
}


/***************************************************************************
*
* so_server - prepare listen for host
*
*
* \retval 0
*	ok
* \retval errno
*	error
*/

int so_server(
	SOCKET_T *sp,		/* the socket descriptor from so_sopen() */
	int portnumber,		/* port number of the service */
	CLIENT_FD_T *client,	/* pointer to client structure */
	int maxClients		/* max number of clients */
	)
{
static struct sockaddr_in servaddr;
int	i;
int     reuse_addr;
int     ret;

    /*
    * Bind our local address so that the client can send to us.
    */
    memset((void *)&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(portnumber);

#ifdef __WIN32__
    /*
     * http://www.itamarst.org/writings/win32sockets.html
     *
     * SO_REUSEADDR is weird 
     * On Windows it lets you bind to the same TCP port multiple times without errors.
     * Verified experimentally by failing test, I never bothered to check out
     * MSDN docs for this one, I just don't use it on Windows.
     */
#else
    reuse_addr = 1;
    ret = setsockopt(sp->sd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
    if (ret < 0) {
	perror("SO_REUSEADDR failed");
    }
#endif

    if (bind(sp->sd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
	perror("bind()");
#ifdef __WIN32__
	fprintf(stderr, "bind() - error %d\n", WSAGetLastError());
#endif /* __WIN32__ */
	so_close(sp);

	return(errno);
    }

    /*
    * Set socket to passive mode and ask kernel to buffer upto LISTENQ (inet.h)
    */
    if (listen(sp->sd, LISTENQ) < 0) {
	perror("listen()");
#ifdef __WIN32__
	fprintf(stderr, "listen() - error %d\n", WSAGetLastError());
#endif /* __WIN32__ */
	so_close(sp);
	return(errno);
    }

    /* initialize client fd array */
    sp->client = client;
    for (i = 0; i < maxClients; i++)  {
	client[i] = -1;
    }
    sp->actClients = 0;
    sp->maxClients = maxClients;

    /* set fd list */
    FD_ZERO(&sp->allset);
    FD_SET(sp->sd, &sp->allset);


    return(0);
}


/***************************************************************************
*
* so_write - write a buffer to a socket stream
*
*
* \retval val
*	the result of the close() call
*/

int so_write(
	int sd,			/* the sockets file descriptor */
	char *buf,		/* pointer where data are put in */
	int len			/* number of bytes to write */
	)
{

#if defined( __WIN32__) || defined(TARGET_IPC)
    return(send(sd, buf, len, 0));
#else
    return(write(sd, buf, len));
#endif

}


/***************************************************************************
*
* so_readline - read a line from socket 
*
* Read a line from a descriptor.  Read the line one byte at a time,
* looking for the newline.  We store the newline in the buffer,
* then follow it with a null (the same as fgets(3)).
* We return the number of characters up to, but not including,
* the null (the same as strlen(3)).
*
* \retval n
*	number of bytes read
*/

int so_readline(
	int fd,			/* the sockets file descriptor */
	char *ptr,		/* pointer where data are put in */
	int maxlen		/* maximum number of bytes to read */
	)
{
int n, rc;
char c;

    for (n = 1; n < maxlen; n++) {
	if ( (rc =
#ifdef __WIN32__
	recv(fd, &c, 1, 0 )
#else
	recv(fd, &c, 1, 0 )	/* geht beides, zeit auch gleich, */
				/* also nehmen wir die kompatible version */
#endif
	) == 1) {
	    /* read exactly one char, like it should do */
	    *ptr++ = c;
	    if (c == '\n') {
		break;
	    }
	} else if (rc == 0) {
	    if (n == 1)  {
		return(0);	/* EOF, no data read */
	    } else  {
		break;		/* EOF, some data was read */
	    }
	} else {	/* rc == -1 ?? */
	    int errno_tmp;
	    errno_tmp = errno;
	    perror("readline(read())");
	    if (errno_tmp == EINTR) {
		continue;
	    } else {
		return(-1);	/* error */
	    }
	}
    }
  
    *ptr = 0;
    return(n);
}


/***************************************************************************
*
* so_server_doit - serve until select call is interrupted
*
* server function waits,
* until the select() call is interrupted.
* The return value describes the reason:
* - error (select returns -1)
* - unknown reason (select returns 0)
* - data from client
* - tcp event (new client, client leaved)
* If the set from select() is known
* then the function read the data from the port
* to the given buffer.
* If there are no data,
* then the port was closed by the client.
* All tcp events (new client, client leave)
* are worked by this function itself.
* 
* \retval SRET_SELECT_ERROR
*	select returns value < 0
* \retval SRET_CONN_FAIL
*	new client connection was not possible
* \retval SRET_UNKNOWN_REASON
*	unknown reason for select interrupt
* \retval SRET_CONN_CLOSED
*	client connection has been closed
*	idx contains the index at the client list
* \retval SRET_CONN_NEW
*	new client connection has been etablished
*	idx contains the index at the client list
* \retval SRET_CONN_DATA
*	data from one of the clients
*	idx contains the index at the client list
*	buffer contains the data and dataCnt the length of the data
* \retval SRET_SELECT_USER
*	select with valid handle from user
*	no data are set
*/
int so_server_doit(
	SOCKET_T *sp,			/* socket pointer */
	int	*index,			/* changed index */
	char	*buffer,		/* pointer to receive buffer */
	int	*dataCnt,		/* max/received data count */
	int	timeout			/* timeout in msec for select call */
					/* Linux: timeout == 0 no timeout */
	)
{
static fd_set rset;				
static int nready = 0;			/* number of file descriptors ready */
int maxfd;
static int idx;
struct timeval tval;			/* use time out in W32 server */
int ret;

    if (nready == 0)  {

	maxfd = sp->sd;			/* only listening to servaddr */
	idx = 0;
	/* find the highest fd */
	while (idx < sp->maxClients) {
	    if (sp->client[idx] >= maxfd) {
		maxfd = sp->client[idx];
	    }
	    idx++;
	}

	if (so_debug > 1) {
	    printf("Waiting for connections on port %d\n", 0);
	    fflush(stdout);
	}

	rset = sp->allset;	/* copy allset (structure assignment) */
 
	/*
	* Wait for one of the file descriptors in rset to be ready for reading
	* (no timeout).
	*/
	/*                             read. write, exc, time   */
#ifdef __WIN32__
	tval.tv_sec = timeout / 1000;
	tval.tv_usec = (timeout % 1000) * 1000;

	nready = select(maxfd+1, &rset, NULL, NULL, &tval);
#else /* __WIN32__ */
	if (timeout == 0) {
	    nready = select(maxfd+1, &rset, NULL, NULL, NULL);
	} else {
	    tval.tv_sec = timeout / 1000;
	    tval.tv_usec = (timeout % 1000) * 1000;
	    nready = select(maxfd+1, &rset, NULL, NULL, &tval);
	}
#endif /* __WIN32__ */
	if (nready < 1) {

	    /* Kann vom Timer Interrupt unterbrochen sein */
	    if (nready == 0) {
		return SRET_UNKNOWN_REASON;
            } else {
		/* < 0  means error */
#ifdef __WIN32__
		fprintf(stderr, "select() - error %d\n",WSAGetLastError());
		so_close(sp);
#endif /* __WIN32__ */
		nready = 0;
		return SRET_SELECT_ERROR;
	    }
	}

	if (so_debug > 0) {
	    /* printf("select returns nready %d\n", nready); */
	    /* fflush(stdout); */
	}
	idx = 0;
    }

    /* nready is > 0 */


    /*
     * While there are remaining fds ready to read,
     * and clients in the array...
    */
    for (idx = 0; ((nready > 0) && (idx < sp->maxClients)); idx++) {

	/* get sock fd */
	int sockfd = sp->client[idx];

	if ( (sockfd >= 0) && (FD_ISSET(sockfd, &rset)) ) {

	    /* signal from this channel */
	    *index = idx;

	    nready--; /* on file descriptor processed */
	    FD_CLR((unsigned int)sockfd, &rset);

	    *dataCnt = so_readline(sockfd, buffer, *dataCnt);
	    if (*dataCnt <= 0) {
		/* n == 0, connection closed by client */
		if (so_debug > 0) {
		    printf("Closing connection fd#%d\n", sockfd);
		    fflush(stdout);
		}
#ifdef __WIN32__
		closesocket(sockfd);
#else /* __WIN32__ */
		close(sockfd);
#endif /* __WIN32__ */

		sp->client[idx] = -1;
		FD_CLR((unsigned int)sockfd, &sp->allset);
		sp->actClients --;

		return SRET_CONN_CLOSED;
	    } else {
		    /*
		     * received data ok
		     */
		return SRET_CONN_DATA;
	    }

	}
    }

    /*
    * Is this a new client connection ?
    */
    if (FD_ISSET(sp->sd, &rset)) {
	int clilen;
	int connfd;
	struct sockaddr_in cliaddr;

	nready--;		/* one file descriptor processed */
	FD_CLR((unsigned int)sp->sd, &rset);

	if (so_debug > 0) {
	    printf("new connection requested\n");
	}

	/*
	* Accept the client connection
	*/
	clilen = sizeof(cliaddr);
	connfd = accept(sp->sd, (struct sockaddr *) &cliaddr, &clilen);
	if (connfd < 0) {
	    perror("accept()");
	    return SRET_CONN_FAIL;
	}

	if (so_debug > 0) {
	    printf("New client: %s, port %d; Assigning fd#%d\n",
	    inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), connfd);
	    fflush(stdout);
	}

	/*
	 * Check for a free entry at the client list
	 */
	idx = 0;
	while (idx < sp->maxClients) {
	    if (sp->client[idx] < 0) {
		break;
	    }
	    idx++;
	}

	if (idx == sp->maxClients) {
	    fprintf(stderr, "Error: too many clients - close it\n");
	    fflush(stderr);
#ifdef __WIN32__
	    closesocket(connfd);
#else /* __WIN32__ */
	    close(connfd);
#endif /* __WIN32__ */
	    return SRET_CONN_FAIL;
	}

	if (so_debug > 0) {
	    printf("New Client at index %d \n", idx);
	}

	sp->client[idx] = connfd;	/* save descriptor */
	*index = idx;

	/* Add the new descriptor to set (maintain maxfd for select) */
	FD_SET(connfd, &sp->allset);
	if (connfd > maxfd) {
	    maxfd = connfd;
	}

	/* maintain the maximum index indicator for the client[] array */
	sp->actClients++;

	if (sock_opt.tcpNoDelay == 1) {
	    /* 
	     * normally the 2. parameter should be SOL_TCP
	     * however IPPROTO seems to be just another/older name
	     * and is also used on windows
	     */
	    ret = setsockopt(sp->sd, IPPROTO_TCP, TCP_NODELAY, &sock_opt.tcpNoDelay,
		sizeof(sock_opt.tcpNoDelay));
	    if (ret < 0) {
		perror("TCP_NODLEAY failed");

	    }
	}

	return SRET_CONN_NEW;
    }

    nready = 0;
    return SRET_SELECT_USER;
}
