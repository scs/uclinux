/* the Music Player Daemon (MPD)
 *
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 *
 * Multi-Processing Model (MPM) abstraction
 * (c) 2004-2005 by Eric Wong (eric@petta-tech.com)
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

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <assert.h>

#include "log.h"
#include "utils.h"
#include "mpm_clone.h"

#include "directory.h"
#include "player.h"
#include "decode.h"
#include "file_buffer.h"

#define clone_flags (CLONE_VM|CLONE_FS|CLONE_FILES|SIGCHLD)
#define MPM_POOL_SIZE (5)
/* STACK_SIZE: increment this as needed to prevent stack corruption
 *   FLAC only needs 0x2000 (8K, fairly certain)
 *   Ogg-Vorbis with tremor needs ~12K
 *   MAD/Ogg-Vorbis/AudioFile seem to need at least 0x20000 (128K)
 *   mikmod/faad/mp4: no idea
 */
static struct _mpm_tasks {
	volatile pid_t id;
	const unsigned int stack_size;
	int (*func)(void *);
	char * stack;
} mpm_tasks [] = { 
	{ 0, 0, NULL, NULL },		/* main process */
	{ 0, 0x20000, update_task, NULL },
	{ 0, 0x20000, player_task, NULL },
	{ 0, 0x20000, decode_task, NULL },
	{ 0, 0x400, filebuf_task, NULL }  /* very small */
};

inline pid_t mpm_clone_get_id (const tid_t task_id)
{
	return mpm_tasks[task_id].id;
}

inline void mpm_clone_set_id (const tid_t task_id, const pid_t pid)
{
	mpm_tasks[task_id].id = pid;
}

inline void mpm_clone_free(const tid_t task_id)
{
	if(!mpm_tasks[task_id].id) {
		free(mpm_tasks[task_id].stack);
		mpm_tasks[task_id].stack = NULL;
	}
}

inline void mpm_clone_stack_debug()
{
#ifdef MPM_STACK_DEBUG
	unsigned int i, j;
	for (i = 2; i < 5; ++i) {
		ERROR("stack_debug %u: %u:\n", i, mpm_tasks[i].stack_size);
		for (j = mpm_tasks[i].stack_size - 1; j != 0; --j) {
			fprintf(stderr,"%c",
			      mpm_tasks[i].stack[j]=='\0' ? '.' : 'x');
			if (!(j % 100))
				fprintf(stderr,"\n%08x ",j);
		}
		fprintf(stderr,"\n");
	}
#endif /* MPM_STACK_DEBUG */
}

pid_t mpm_clone_spawn (const tid_t task_id, void * arg)
{
	pid_t pid;
	if (mpm_tasks[task_id].stack)
		free(mpm_tasks[task_id].stack);
	
	mpm_tasks[task_id].stack = malloc(mpm_tasks[task_id].stack_size);
	memset(mpm_tasks[task_id].stack,'\0',mpm_tasks[task_id].stack_size);
	
	pid = clone( mpm_tasks[task_id].func,
		     mpm_tasks[task_id].stack
		       + (mpm_tasks[task_id].stack_size - STACK_HEAD_OFFSET),
		     clone_flags,
		     arg);

	if (pid < 0) {
		ERROR("clone() failed with errno: %i\n",errno);
		mpm_clone_free(task_id);
		mpm_clone_set_id(task_id,0);
		return -1; /* make it like fork(); */
	} else if (pid > 0)
		mpm_tasks[task_id].id = pid;

	return pid;
}

inline void mpm_clone_enter (const tid_t task_id)
{
	mpm_tasks[task_id].id = getpid();
	return;
}

inline void mpm_clone_init ()
{
	mpm_clone_enter(MPM_MAIN);
}

inline void mpm_clone_finish ()
{
	unsigned int i;
	mpm_clone_enter(MPM_MAIN);
	for (i=1;i<MPD_TLS_MAX;++i) {
		if (mpm_tasks[i].stack != NULL)
			free(mpm_tasks[i].stack);
	}
}

/* don't call error or print functions inside this function: */
inline char * mpm_clone_maxpath_str ()
{
	static volatile unsigned i = 0;
	static char path[MPM_POOL_SIZE][MAXPATHLEN+1];
	return path[(++i%MPM_POOL_SIZE)];
}

