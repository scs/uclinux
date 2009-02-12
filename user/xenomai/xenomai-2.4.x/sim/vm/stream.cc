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
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "vm/stream.h"

const int MvmStreamBufSize = 2048;

MvmStream MvmDebug(new MvmChannel); // defaults to stderr

void MvmChannel::connect () {}

void *MvmChannel::input (void *, int& nbytes)

{
    nbytes = -1;
    return NULL;
}

int MvmChannel::output (void *buf, int nbytes) {

    return ::write(2,(const char *)buf,nbytes);
}

// Basic I/O stream

MvmStream::MvmStream (MvmChannel *_channel, const char *s)

{
    channel = _channel;

    if (s && (len = strlen(s)) > 0)
	{
	content = new char[len];
	memcpy(content,s,len);
	}
    else
	{
	len = 0;
	content = NULL;
	}
}

// NOTE: channel is not closed in ~MvmStream() because temporary
// MvmStream objects are constructed during the concatenation
// process using the existing channel. As a channel can be an
// identified system resource, it cannot be closed more than once.
// It's up to the caller which destroys an MvmStream to close the
// associated channel.

MvmStream::~MvmStream ()

{
    if (len > 0)
	delete[] (char *)content;
}

MvmStream& MvmStream::operator<< (const char *s)

{
    if (s)
	return *this << MvmStream(channel,s);

    return *this << MvmStream(channel,"(null)");
}

MvmStream& MvmStream::operator<< (int n)

{
    return *this << MvmStream(channel,CString(n));
}

MvmStream& MvmStream::operator<< (char c)

{
    if (c)
	{
	char s[2];
	s[0] = c;
	s[1] = '\0';
	return *this << MvmStream(channel,s);
	}

    flush();

    return *this;
}

MvmStream& MvmStream::operator<< (unsigned int n)

{
    return *this << MvmStream(channel,CString(n));
}

MvmStream& MvmStream::operator<< (long l)

{
    return *this << MvmStream(channel,CString(l));
}

MvmStream& MvmStream::operator<< (unsigned long ul)

{
    return *this << MvmStream(channel,CString(ul));
}

MvmStream& MvmStream::operator<< (double g)

{
    return *this << MvmStream(channel,CString(g));
}

MvmStream& MvmStream::operator<< (void *p)

{
    return *this << MvmStream(channel,CString(p));
}

MvmStream& MvmStream::operator<< (const ETime& et)

{
    *this << et.getUSec() / TimeValue[et.getUnit()]
	  << " " << TimeString[et.getUnit()];
    return *this;
}

MvmStream& MvmStream::operator<< (const ITime& it)

{
    *this << it.format();
    return *this;
}

MvmStream& MvmStream::operator<< (const MvmStream& r)

{
    int eol = r.len - 1;

    while (eol >= 0 && *((char *)r.content + eol) != '\n')
	eol--;

    if (eol >= 0)
	{
	int l = eol + 1;

	if (len + l > 0)
	    {
	    void *newcontent = new char[l + len];

	    if (len > 0)
		memcpy(newcontent,content,len);

	    if (l > 0)
		memcpy((char *)newcontent + len,r.content,l);

	    if (content)
		delete[] (char *)content;

	    content = newcontent;
	    len += l;
	    flush();

	    if (len + r.len - l > 0)
		{
		// flush can be delayed - can't assume this stream
		// was actually flushed.
		void *newcontent = new char[len + r.len - l];

		if (len > 0) // wasn't flushed at all!!
		    {
		    memcpy(newcontent,content,len);
		    delete[] (char *)content;
		    }

		memcpy((char *)newcontent + len,
		       (char *)r.content + l,
		       r.len - l);
		content = newcontent;
		len += r.len - l;
		}
	    else
		content = NULL;
	    }
	}
    else
	{
	if (len + r.len > 0)
	    {
	    void *newcontent = new char[len + r.len];

	    if (len > 0)
		memcpy(newcontent,content,len);

	    if (r.len > 0)
		memcpy((char *)newcontent + len,
		       r.content,
		       r.len);
	    if (content)
		delete[] (char *)content;

	    content = newcontent;
	    len += r.len;

	    if (len >= MvmStreamBufSize)
		flush();
	    }
	}

    return *this;
}

void MvmStream::flush ()

{
    if (len > 0)
	{
	// output() should return a positive (or null)
	// value if the flush was actually performed
	int n;

	if ((n = channel->output(content,len)) > 0)
	    {
	    if (len - n <= 0) // the full data string has been sent
		{
		delete[] (char *)content;
		content = NULL;
		len = 0;
		}
	    else
		{
		// only a partial data string was sent
		len -= n;
		char *newcontent = new char[len];
		memcpy(newcontent,(char *)content + n,len);
		delete[] (char *)content;
		}
	    }
	}
}

MvmStream& MvmStream::operator>> (void *p)

{
    content = channel->input(content,len);

    if (len > 0)
	{
	memcpy(p,content,len);
	delete[] (char *)content;
	content = NULL;
	len = 0;
	}

    return *this;
}
