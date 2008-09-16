/* the Music Player Daemon (MPD)
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 *
 * Multi-Processing Model (MPM) abstraction layer
 * (c) 2004 by Eric Wong <eric@petta-tech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef MPM_H
#define MPM_H

#include <string.h>
#include <sys/param.h>
#include <stdio.h>

#include "mpm_clone.h"

#ifndef MPM_MODEL
# error "MPM_MODEL not defined!\n"
#endif /* MPM_MODEL */
#ifndef MPD_TLS_MAX 
# error "MPD_TLS_MAX not defined by current mpm model: "MPM_MODEL 
#endif /* MPD_TLS_MAX */

/* 
 * mpm_spawn: spawns a new child to enter a function with args
 * 	function: function to enter
 * 	args: args to enter function with
 *      returns: pid of forked process or thread_id of child thread
 *
 * mpm_task_id: returns the id number of the current process
 * 
 * mpm_exit: exits the thread with status
 * 	returns: never 
 *
 * mpm_init: initialize global variable pool ( only run in main() )
 *
 * mpm_get_id: get the pid of a certain task
 */

#define mpm_spawn(task_id,arg)    mpm_clone_spawn(task_id,arg)
#define mpm_enter(task_id)        mpm_clone_enter(task_id)
#define mpm_get_id(task_id)       mpm_clone_get_id(task_id)
#define mpm_set_id(task_id,pid)   mpm_clone_set_id(task_id,pid)
#define mpm_init()                mpm_clone_init()
#define mpm_finish()              mpm_clone_finish()
#define mpm_free(task_id)         mpm_clone_free(task_id)
#define mpm_maxpath_str()         mpm_clone_maxpath_str()
#define mpm_stack_debug()         mpm_clone_stack_debug()

#endif /* MPM_H */

