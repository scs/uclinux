/* Return list of symbols the library can request.
   Copyright (C) 2001, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 2001.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <assert.h>
#include "thread_dbP.h"

#ifdef __ARCH_HAS_C_SYMBOL_PREFIX__
#define THREAD_SYMBOL_PREFIX __C_SYMBOL_PREFIX__
#else
#define THREAD_SYMBOL_PREFIX ""
#endif

static const char *symbol_list_arr[] =
{
  [PTHREAD_THREADS_EVENTS] = THREAD_SYMBOL_PREFIX "__pthread_threads_events",
  [PTHREAD_LAST_EVENT] = THREAD_SYMBOL_PREFIX "__pthread_last_event",
  [PTHREAD_HANDLES_NUM] = THREAD_SYMBOL_PREFIX "__pthread_handles_num",
  [PTHREAD_HANDLES] = THREAD_SYMBOL_PREFIX "__pthread_handles",
  [PTHREAD_KEYS] = THREAD_SYMBOL_PREFIX "pthread_keys",
  [LINUXTHREADS_PTHREAD_THREADS_MAX] = THREAD_SYMBOL_PREFIX "__linuxthreads_pthread_threads_max",
  [LINUXTHREADS_PTHREAD_KEYS_MAX] = THREAD_SYMBOL_PREFIX "__linuxthreads_pthread_keys_max",
  [LINUXTHREADS_PTHREAD_SIZEOF_DESCR] = THREAD_SYMBOL_PREFIX "__linuxthreads_pthread_sizeof_descr",
  [LINUXTHREADS_CREATE_EVENT] = THREAD_SYMBOL_PREFIX "__linuxthreads_create_event",
  [LINUXTHREADS_DEATH_EVENT] = THREAD_SYMBOL_PREFIX "__linuxthreads_death_event",
  [LINUXTHREADS_REAP_EVENT] = THREAD_SYMBOL_PREFIX "__linuxthreads_reap_event",
  [LINUXTHREADS_INITIAL_REPORT_EVENTS] = THREAD_SYMBOL_PREFIX "__linuxthreads_initial_report_events",
  [LINUXTHREADS_VERSION] = THREAD_SYMBOL_PREFIX "__linuxthreads_version",
  [NUM_MESSAGES] = NULL
};


const char **
td_symbol_list (void)
{
  return symbol_list_arr;
}


int
td_lookup (struct ps_prochandle *ps, int idx, psaddr_t *sym_addr)
{
  assert (idx >= 0 && idx < NUM_MESSAGES);
  return ps_pglobal_lookup (ps, LIBPTHREAD_SO, symbol_list_arr[idx], sym_addr);
}
