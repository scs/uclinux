/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#ifdef HAVE_NETINET_TCP
#include <netinet/tcp.h>
#endif // !HAVE_NETINET_TCP
#include <errno.h>
#include <netdb.h>
#include <memory.h>
#include "vm/thread.h"
#include "vm/pipe.h"

// MvmPipe - client/server TCP-interface keeping packet
// boundaries. Can be used as MvmScheduler callout
// object for asynch. I/O. 3 management modes exist:
// - client mode using MvmPipe::MvmPipe(): MvmPipe::connect()
// must be issued before data can actually be sent or received
// on the client channel.
// - master server mode using MvmPipe::MvmPipe(): MvmPipe::bind()
// followed by MvmPipe::accept() must be issued before data can
// actually be sent or received on the server channel.
// - slave mode using MvmPipe::MvmPipe(int): the socket
// descriptor is passed as an argument.
// IMPORTANT NOTE: A usual bug may be encountered with boxes
// having strict alignment rules for objects in memory (such as
// SPARC boxes have). When passing double values (let us say, aligned
// on 64bits boundaries) in structs transmitted from peer-to-peer
// using a MvmPipe channel, one *must* use dynamically allocated memory
// (i.e. from new() or direct malloc()) to hold the i/o buffer and
// *never* statically-defined memory (such as an array of bytes inside
// a class or even more an automatic character array in a stack frame,
// which could actually be aligned on smallest boundaries -- unless the
// alignment constraint is enforced by the mean of explicit padding);
// this way one may assume that the allocator will pass back 64bits-aligned
// memory blocks if this is the usual rule on the system, thus making the
// compiler offset computations right if it depends on this assumption
// when laying binary objects in memory.
// Otherwise, many bus errors will be raised...!
// Dynamic allocation of smbuf/dmbuf illustrates this point.

MvmPipe::MvmPipe () :
    MvmListener(-1)
{
    connSock = -1;
    dmbuf = NULL;
    smbuf = new char[MVM_PIPE_MBUFSZ];
    memset(smbuf,0,MVM_PIPE_MBUFSZ); // to please Purify et al.
}

// MvmPipe::MvmPipe(int) - allows reusing an already open
// socket as the underlying O/S channel.

MvmPipe::MvmPipe (int _connSock) :
    MvmListener(_connSock)
{
    connSock = _connSock;
    in.sin_port = htons(0);
    dmbuf = NULL;
    smbuf = new char[MVM_PIPE_MBUFSZ];
    memset(smbuf,0,MVM_PIPE_MBUFSZ); // to please Purify et al.
}

// MvmPipe::~MvmPipe() closes the TCP end-point only if it
// has been connected through MvmPipe::connect(); the inet
// port value distinguishes between controlled and
// uncontrolled socket connection (i.e. 0 means the
// connection was done by the caller, outside MvmPipe's
// control).

MvmPipe::~MvmPipe ()

{
    dispose();
    
    if (connSock != -1 && in.sin_port != 0)
	::close(connSock);

    delete[] smbuf;
}

int MvmPipe::connect (const char *host, int port)

{
    if (!host)
	host = "localhost";
	
    struct hostent *hostent = gethostbyname(host);

    if (!hostent || hostent->h_addrtype != AF_INET)
	return MVM_PIPE_LINKDOWN;

    memset(&in,0,sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(port);
    memcpy(&in.sin_addr,hostent->h_addr,sizeof(in_addr));

    int s = ::socket(AF_INET,SOCK_STREAM,PF_UNSPEC);

    if (s == -1)
	return MVM_PIPE_LINKDOWN;
    
    if (::connect(s,(struct sockaddr *)&in,sizeof(in)) < 0)
	{
	::close(s);
	return MVM_PIPE_LINKDOWN;
	}

    // disable Nagle algorithm (no packet coalescence)
    int solopt = 1;
    setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&solopt,sizeof(solopt));
    connSock = s;
    addFildes(s);

    return MVM_PIPE_SUCCESS;
}

int MvmPipe::bind (int port)

{
    int s = ::socket(AF_INET,SOCK_STREAM,PF_UNSPEC);

    if (s == -1)
	return MVM_PIPE_FAILURE;

    int solopt = 1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char *)&solopt,sizeof(solopt));
    
    // accept connections from any networks/hosts
    memset(&in,0,sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(port);
    in.sin_addr.s_addr = htonl(INADDR_ANY);

    int r = ::bind(s,(struct sockaddr *)&in,sizeof(in));
    socklen_t len = sizeof(in);

    if (r < 0 ||
	::listen(s,SOMAXCONN) < 0 ||
	::getsockname(s,(struct sockaddr *)&in,&len) < 0)
	{
	::close(s);
	return MVM_PIPE_FAILURE;
	}

    connSock = s;

    return ntohs(in.sin_port);
}

int MvmPipe::accept (u_long timeout)

{
    struct timeval tv = { timeout, 0 };
    fd_set pollMask;

    FD_ZERO(&pollMask);
    FD_SET(connSock,&pollMask);
    int n = ::select(FD_SETSIZE,
		     &pollMask,
		     NULL,
		     NULL,
		     timeout > 0 ? &tv : 0);
    if (n == 0)
	// timeout event -- no conn within
	// the specified time.
	return MVM_PIPE_WOULDBLOCK;

    if (n < 0)
	// bad channel???
	return MVM_PIPE_LINKDOWN;
    
    int clntSock = ::accept(connSock,NULL,NULL);
    ::close(connSock);
    // swap server socket with connection end-point
    connSock = clntSock;

    if (connSock < 0)
	return MVM_PIPE_LINKDOWN;

    addFildes(connSock);

    return MVM_PIPE_SUCCESS;
}

// MvmPipe::send() emits a message on the connected socket; empty
// messages are accepted (i.e. a message type information is sent
// alone on the stream).

int MvmPipe::send (int mid, const void *mbuf, int nbytes)

{
    u_long h[2];

    h[0] = htonl((u_long)nbytes);
    h[1] = htonl((u_long)mid);

    // Use I/O vectors for efficiency.  Assume that signals are
    // configured so that syscalls are restarted upon signal receipt.
    struct iovec iov[2]; int iovcnt = 1;
    iov[0].iov_base = (caddr_t)h;
    iov[0].iov_len = sizeof(h);

    if (nbytes > 0)
	{
	iov[1].iov_base = (caddr_t)mbuf;
	iov[1].iov_len = nbytes;
	iovcnt++;
	}

    if ((unsigned)::writev(connSock,iov,iovcnt) != nbytes + sizeof(h))
	return MVM_PIPE_LINKDOWN;

    return nbytes;
}

int MvmPipe::recv (void **mbufp, int *ubytes)

{
    u_long h[2];
    int n = 0, l;

    do
	{
	l = ::recv(connSock,(char *)h + n,sizeof(h) - n,0);
	n += l;
	}
    while (l > 0 && (unsigned)n < sizeof(h));

    if (l <= 0)
	return MVM_PIPE_LINKDOWN;

    int nbytes = (int)ntohl(h[0]); // fetch actual message size
    int mid = (int)ntohl(h[1]); // fetch message id

    if (nbytes > 0)
	{
	if (nbytes <= MVM_PIPE_MBUFSZ)
	    {
	    // current message fits in the static message area:
	    // so use it to hold the incoming message (also dispose
	    // from the last dynamic area allocated (if any) before
	    // proceeding).
	    dispose();
	    *mbufp = smbuf;
	    }
	else
	    {
	    // current message is too large to fit in the static
	    // area: allocate a dynamic buffer to hold it, after
	    // an attempt to recycle a -non-disposed- previously
	    // allocated buffer (if its size is sufficient).
	    
	    if (dmbuf && dmsize < nbytes)
		dispose();

	    if (!dmbuf)
		{
		dmbuf = new char[nbytes];
		memset(dmbuf,0,nbytes); // to please Purify et al.
		}
	    
	    *mbufp = dmbuf;
	    dmsize = nbytes;
	    }

	n = 0;
	
	do
	    {
	    l = ::recv(connSock,(char *)*mbufp + n,nbytes - n,0);
	    n += l;
	    }
	while (l > 0 && n < nbytes);

	if (l <= 0)
	    return MVM_PIPE_LINKDOWN;
	}
    else
	*mbufp = NULL;

    *ubytes = nbytes;
    
    return mid;
}

int MvmPipe::poll (void **mbufp, int *ubytes)

{
    if (MvmListener::poll(NULL) != 0)
	// this means that -1 returned from poll() will
	// certainly beget a linkdown status from recv().
	return recv(mbufp,ubytes);

    return MVM_PIPE_WOULDBLOCK;
}

void MvmPipe::dispose ()

{
    if (dmbuf)
	{
	delete[] dmbuf;
	dmbuf = NULL;
	}
}
