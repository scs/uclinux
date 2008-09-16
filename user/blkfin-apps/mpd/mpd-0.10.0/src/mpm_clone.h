/* the Music Player Daemon (MPD)
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 *
 * Multi-Processing Model (MPM) abstraction
 * (c) 2004 by Eric Wong (eric@petta-tech.com)
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

/*
 * mpd multiprocessing clone() management code
 * do not #include this file, only mpm.h (which includes this)
 */

#ifndef MPM_CLONE_H
#define MPM_CLONE_H

#define MPM_MODEL "clone"

typedef unsigned int tid_t;

#include <string.h>
#include <stdlib.h>

#define MPM_MAIN	0 /* the main mpd parent task */
#define MPM_UPDATE	1 /* the update task */
#define MPM_PLAYER	2 /* the player task */
#define MPM_DECODE	3 /* the decoder task */
#define MPM_FILEBUF	4 /* the file buffering task */
#define MPD_TLS_MAX	5 

/* STACK_HEAD_OFFSET 88: found by trial-and-error for the arm7tmdi */
#ifndef STACK_HEAD_OFFSET
# define STACK_HEAD_OFFSET 88
#endif /* STACK_HEAD_OFFSET */

inline void mpm_clone_exit (const int status);
inline void mpm_clone_enter (const tid_t task_id);
pid_t mpm_clone_spawn (const tid_t task_id, void * arg);
inline pid_t mpm_clone_get_id(const tid_t task_id);
inline void mpm_clone_set_id(const tid_t task_id, const pid_t pid);
inline void mpm_clone_init();
inline void mpm_clone_finish();
inline void mpm_clone_free(const tid_t task_id);
inline char *mpm_clone_maxpath_str();
inline void mpm_clone_stack_debug();
#endif /* MPM_CLONE_H */

