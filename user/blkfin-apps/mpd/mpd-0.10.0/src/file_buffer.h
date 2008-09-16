/* the Music Player Daemon (MPD)
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 * 
 * File input buffer for slow disks on ipods and laptops.
 * (c) 2004 by Eric Wong <eric@petta-tech.com>
 *
 * Geeks attempting to rap ...
 *     shank: i like big buffers, i cannot lie
 *     mackstann: you other coders can't deny
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
#include "inputStream.h"

/*
 * We'll use O_STREAMING in uClinux 2.4 for the ipod.  It's described
 * here: http://www.kernel.org/pub/linux/kernel/people/rml/O_STREAMING/
 */
#ifndef O_STREAMING
# define O_STREAMING    04000000        /* streaming access */
#endif /* O_STREAMING */

/* We create FILE_BUFFER_BLKS separate arrays of 1M each since the malloc
 * implementation on uClinux is weak, and can't allocate more than 1M.  If we
 * chose the one that worked for up to 7M, then our disk access speed suffers
 * greatly
 */
#define FILE_BUFFER_BLKS     16
#define FILE_BUFFER_BLKSIZE  (1000*1024)
#define FILE_BUFFER_SIZE     (FILE_BUFFER_BLKS * FILE_BUFFER_BLKSIZE)

typedef struct _InputStream_file_data {
	unsigned int fd;
	int cur;
	unsigned int roll;
} InputStream_file_data;

/* move buffer head and tail pointers to offset */
inline void buffer_reset(int offset);

/* create a new file data object */
inline InputStream_file_data * new_file_data (const int fd);

/* initialize and allocate memory for the file buffer */
void init_file_buffer();

/* free and release memory used by the file buffer */
void finish_file_buffer();

/* like read(), but from the buffer instead */
inline size_t read_file_buffer(InputStream * inStream, void * ptr,
		size_t size, size_t nmemb);

/* cur_stream functions: cur stream is what we use for async buffer-filling */
/* set cur_stream to inStream if cur_stream == NULL*/
inline void set_cur_stream_cond(InputStream *inStream);

/* sets cur_stream to NULL */
inline void clear_cur_stream();

/* clears cur_stream if cur_stream == inStream */
inline void clear_cur_stream_cond(InputStream *inStream);

/* fills the buffer with data pointed to by cur_stream */
inline void fill_current_instream();

int filebuf_task (void *nothing);
