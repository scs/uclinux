/* -*- C++ -*-
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

#ifndef _mvm_pipe_h
#define _mvm_pipe_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "vm/timed.h"

#define MVM_PIPE_MBUFSZ     4096

#define MVM_PIPE_SUCCESS    (0)
#define MVM_PIPE_FAILURE    (-1)
#define MVM_PIPE_LINKDOWN   MVM_PIPE_FAILURE
#define MVM_PIPE_WOULDBLOCK (-2)

class MvmPipe : public MvmListener {

protected:

    int connSock;

    struct sockaddr_in in;

    char *smbuf,
	*dmbuf;

    int dmsize;

public:

    MvmPipe();

    MvmPipe(int connSock);

    virtual ~MvmPipe();

    int getHandle() const {
	return connSock;
    }

    int connect(const char *host,
		int port);

    int bind(int port =0);

    int accept(u_long timeout =0);

    int send(int mid,
	     const void *mbuf =0,
	     int nbytes =0);

    int recv(void **mbufp,
	     int *ubytes);

    int poll(void **mbufp,
	     int *ubytes);

    void dispose();
};

#endif // !_mvm_pipe_h
