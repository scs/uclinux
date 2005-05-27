/* Copyright (C) 2001 Free Software Foundation, Inc.

   This file is part of GNU Inetutils.

   GNU Inetutils is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   GNU Inetutils is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Inetutils; see the file COPYING.  If not, write to
   the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA. */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/param.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

int
login_tty(int ttyfd)
{
  int fd;
  char *fdname;

#ifdef HAVE_SETSID
  setsid();
#endif
#ifdef HAVE_SETPGID
  setpgid(0, 0);
#endif
	
  /* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (fd >= 0)
    {
      ioctl(fd, TIOCNOTTY, NULL);
      close(fd);
    }
  else
    syslog(LOG_WARNING, "NO CTTY");
#endif /* TIOCNOTTY */
  
  /* Verify that we are successfully disconnected from the controlling tty. */
  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (fd >= 0)
    {
      syslog(LOG_WARNING, "Failed to disconnect from controlling tty.");
      close(fd);
    }
  
  /* Make it our controlling tty. */
#ifdef TIOCSCTTY
  ioctl(ttyfd, TIOCSCTTY, NULL);
#endif /* TIOCSCTTY */

  fdname = ttyname (ttyfd);
  fd = open(fdname, O_RDWR);
  if (fd < 0)
    syslog(LOG_WARNING, "open %s: %s", fdname, strerror(errno));
  else
    close(fd);

  /* Verify that we now have a controlling tty. */
  fd = open("/dev/tty", O_WRONLY);
  if (fd < 0)
    {
      syslog(LOG_WARNING, "open /dev/tty: %s", strerror(errno));
      return 1;
    }

  close(fd);
#if defined(HAVE_VHANGUP) && !defined(HAVE_REVOKE)
  {
    RETSIGTYPE (*sig)();
    sig = signal(SIGHUP, SIG_IGN);
    vhangup();
    signal(SIGHUP, sig);
  }
#endif
  fd = open(fdname, O_RDWR);
  if (fd == -1)
    {
      syslog(LOG_ERR, "can't reopen ctty %s: %s", fdname, strerror(errno));
      return -1;
    }
	
  close(ttyfd);

  if (fd != 0)
    close(0);
  if (fd != 1)
    close(1);
  if (fd != 2)
    close(2);

  dup2(fd, 0);
  dup2(fd, 1);
  dup2(fd, 2);
  if (fd > 2)
    close(fd);
  return 0;
}

