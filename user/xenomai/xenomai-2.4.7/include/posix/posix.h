/*
 * Copyright (C) 2003 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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
 */

#ifndef _XENO_SKIN_POSIX_H
#define _XENO_SKIN_POSIX_H

#define PSE51_SKIN_VERSION_STRING  "1.0"
#define PSE51_SKIN_VERSION_CODE    0x00010000
#define PSE51_SKIN_MAGIC           0x50534531

#ifdef __XENO_SIM__

#include <posix/errno.h>
#include <posix/pthread.h>
#include <posix/sched.h>
#include <posix/signal.h>
#include <posix/semaphore.h>
#include <posix/mqueue.h>
#include <posix/time.h>
#include <posix/fcntl.h>
#include <posix/unistd.h>
#include <posix/sys/mman.h>
#include <posix/sys/ioctl.h>
#include <posix/sys/socket.h>

#else /* !__XENO_SIM */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <semaphore.h>
#include <mqueue.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#endif /* !__XENO_SIM */

#endif /* !_XENO_SKIN_POSIX_H */
