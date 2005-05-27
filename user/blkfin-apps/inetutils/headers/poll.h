/* Compatibility definitions for System V `poll' interface.
   Copyright (C) 1994, 1996, 1997, 1998, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef	_POLL_H
#define	_POLL_H	1

#ifndef __P
# ifdef __STDC__
#  define __P(args) args
# else
#  define __P(args) ()
# endif
#endif /* __P */

/* Normal data can be read.  */
# define POLLRDNORM   0x001
/* Priority ban dat can be read.  */
# define POLLRDBAND   0x002
/* Normal or priority band data can be read.  */
#define POLLIN        (POLLRDNORM | POLLRDBAND)

/* High-priority data can be read.  */
#define POLLPRI       0x004

/* Normal data can be written.  */
#define POLLWRNORM   0x008
/* Priority band data can be written.  */
#define POLLWRBAND   0x010
/* Normal data can be written.  */
#define POLLOUT       (POLLWRNORM)

/* An error has occured. */
#define POLLERR       0x020
/* Hangup has occurred.  */
#define POLLHUP       0x040
/* Descriptors is not an open file.  */
#define POLLNVAL      0x080

#define INFTIM	(-1)

/* Data structure describing a polling request.  */
struct pollfd
  {
    int fd;			/* File descriptor to poll.  */
    short int events;		/* Types of events poller cares about.  */
    short int revents;		/* Types of events that actually occurred.  */
  };

extern int poll __P ((struct pollfd *fds, unsigned long int nfds,
		      int timeout));

#endif	/* _POLL_H */
