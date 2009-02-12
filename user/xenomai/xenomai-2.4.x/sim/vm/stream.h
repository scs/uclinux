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

#ifndef _mvm_stream_h
#define _mvm_stream_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <unistd.h>
#include "vmutils/list++.h"
#include "vmutils/clock.h"

// Raw I/O channel

class MvmChannel {

public:

    virtual void connect();

    virtual void *input(void *buf, int& nbytes);

    virtual int output(void *buf, int nbytes);
};

// Fundamental I/O stream

class MvmStream : public LinkedObject {

    friend class MvmChannel;

protected:

    MvmChannel *channel;

    void *content;

    int len;

public:

    MvmStream(MvmChannel *channel, const char *s =0);

    virtual ~MvmStream();

    MvmStream& operator<<(const char *s);

    MvmStream& operator<<(int n);

    MvmStream& operator<<(char c);

    MvmStream& operator<<(unsigned int u);

    MvmStream& operator<<(double g);

    MvmStream& operator<<(float f) {
	return *this << (double)f;
    }

    MvmStream& operator<<(long l);

    MvmStream& operator<<(unsigned long ul);

    MvmStream& operator<<(void *outp);

    MvmStream& operator<<(short h) {
	return *this << (int)h;
    }

    MvmStream& operator<<(unsigned short uh) {
	return *this << (unsigned int)uh;
    }

    MvmStream& operator<<(const ETime& et);

    MvmStream& operator<<(const ITime& it);

    MvmStream& operator<<(const MvmStream& ios);

    MvmStream& operator>>(void *inp);

    void flush();

    int count() {
	return len;
    }
};

MakeGList(MvmStream);

extern const int MvmStreamBufSize;

extern MvmStream MvmDebug;

#endif // !_mvm_stream_h
