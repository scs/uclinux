/* Copyright (C) 1994, 1996, 1997, 2000 Free Software Foundation, Inc.
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

/* To: libc-alpha@cygnus.com
   Subject: poll emulation
   From: James Antill <james@and.org>
   Reply-To: <james@and.org>
   Date: 15 Mar 1999 23:23:47 +0000  */

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
   an event to occur; if TIMEOUT is -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <poll.h>
#include <time.h>
#include <sys/select.h>
#include <errno.h>

int
poll (struct pollfd *fds, unsigned long nfds, int timeout)
{
  struct timeval tv;
  fd_set rset, wset, xset;
  struct pollfd *f;
  int ready;
  int maxfd = 0;

  FD_ZERO (&rset);
  FD_ZERO (&wset);
  FD_ZERO (&xset);

  for (f = fds; f < &fds[nfds]; ++f)
    if (f->fd != -1)
      {
	f->revents = 0;

	if (f->events & POLLIN)
	  FD_SET (f->fd, &rset);
	if (f->events & POLLOUT)
	  FD_SET (f->fd, &wset);
	if (f->events & POLLPRI)
	  FD_SET (f->fd, &xset);
	if (f->fd > maxfd && (f->events & (POLLIN|POLLOUT|POLLPRI)))
	  maxfd = f->fd;
      }

  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;

  ready = select (maxfd + 1, &rset, &wset, &xset,
		  timeout == -1 ? NULL : &tv);
  if ((ready == -1) && (errno == EBADF))
    {
      ready = 0;

      FD_ZERO (&rset);
      FD_ZERO (&wset);
      FD_ZERO (&xset);

      maxfd = -1;

      for (f = fds; f < &fds[nfds]; ++f)
	if (f->fd != -1)
	  {
	    fd_set sngl_rset, sngl_wset, sngl_xset;

	    FD_ZERO (&sngl_rset);
	    FD_ZERO (&sngl_wset);
	    FD_ZERO (&sngl_xset);

	    if (f->events & POLLIN)
	      FD_SET (f->fd, &sngl_rset);
	    if (f->events & POLLOUT)
	      FD_SET (f->fd, &sngl_wset);
	    if (f->events & POLLPRI)
	      FD_SET (f->fd, &sngl_xset);

	    if (f->events & (POLLIN|POLLOUT|POLLPRI))
	      {
		struct timeval sngl_tv;

		sngl_tv.tv_sec = 0;
		sngl_tv.tv_usec = 0;

		if (select(f->fd + 1,
			   &sngl_rset, &sngl_wset, &sngl_xset, &sngl_tv) != -1)
		  {
		    if (f->events & POLLIN)
		      FD_SET (f->fd, &rset);
		    if (f->events & POLLOUT)
		      FD_SET (f->fd, &wset);
		    if (f->events & POLLPRI)
		      FD_SET (f->fd, &xset);

		    if (f->fd > maxfd
			&& (f->events & (POLLIN|POLLOUT|POLLPRI)))
		      maxfd = f->fd;
		    ++ready;
		  }
		else if (errno == EBADF)
		  f->revents = POLLNVAL;
		else
		  return (-1);
	      }
	  }

      if (ready)
	{ /* Linux alters the tv struct... but it shouldn't matter here ...
	   * as we're going to be a little bit out anyway as we've just eaten
	   * more than a couple of cpu cycles above */
	  ready = select (maxfd + 1, &rset, &wset, &xset,
			  timeout == -1 ? NULL : &tv);
	} /* what to do here ?? */
    }

  if (ready > 0)
    for (f = fds; f < &fds[nfds]; ++f)
      if (f->fd != -1)
	{
	  if (FD_ISSET (f->fd, &rset))
	    f->revents |= POLLIN;
	  if (FD_ISSET (f->fd, &wset))
	    f->revents |= POLLOUT;
	  if (FD_ISSET (f->fd, &xset))
	    f->revents |= POLLPRI;
	}

  return ready;
}
