/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <native/syscall.h>
#include <native/pipe.h>

extern int __native_muxid;

int rt_pipe_create(RT_PIPE *pipe, const char *name, int minor, size_t poolsize)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_pipe_create, pipe, name, minor,
				 poolsize);
}

int rt_pipe_bind(RT_PIPE *pipe, const char *name, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_pipe_bind, pipe, name, &timeout);
}

int rt_pipe_delete(RT_PIPE *pipe)
{
	return XENOMAI_SKINCALL1(__native_muxid, __native_pipe_delete, pipe);
}

ssize_t rt_pipe_read(RT_PIPE *pipe, void *buf, size_t size, RTIME timeout)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_pipe_read, pipe, buf, size, &timeout);
}

ssize_t rt_pipe_write(RT_PIPE *pipe, const void *buf, size_t size, int mode)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_pipe_write, pipe, buf, size, mode);
}

ssize_t rt_pipe_stream(RT_PIPE *pipe, const void *buf, size_t size)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_pipe_stream, pipe, buf, size);
}
