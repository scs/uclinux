/* the Music Player Daemon (MPD)
 * (c)2003-2005 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 * 
 * File input buffer for slow disks on ipods and laptops.
 * (c) 2004-2005 by Eric Wong <eric@petta-tech.com>
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
#include "log.h"
#include "utils.h"
#include "file_buffer.h"
#include "sig_handlers.h"
#include "mpm.h"

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <assert.h>

#define READ_SIZE  (0x1000)
/* cur_stream points to the inputStream we want to fill
 * asynchronously from the decoder */
static volatile InputStream * cur_stream = NULL;

/* if this is set, cur_stream will be filled by this amount at next fill */
static volatile unsigned int fast_fill = 0;

/* make these volatile if more threads access them */
static volatile unsigned int buffer_head, buffer_tail;
static volatile unsigned int buffer_loops = 0;
static unsigned char * file_buffer[FILE_BUFFER_BLKS];

static volatile unsigned int read_lock = 0;

/**
 * virt_to_buffer - translate a virtual address (buffer_head/buffer_tail)
 * to a file_buffer[block] + offset (virtual) address
 * @addr: address to translate
 * @block: which block of the buffer we're in (0 - (FILE_BUFFER_BLKS-1))
 * @offset: where in @block we're in (0 - FILE_BUFFER_BLKSIZE)
 * @count: how much data we can get out of this block
 * @want: how much data we want
 */
#define virt_to_buffer(addr,block,offset,count,want) do { \
	block = addr / FILE_BUFFER_BLKSIZE; \
	offset = addr % FILE_BUFFER_BLKSIZE; \
	while (block >= FILE_BUFFER_BLKS) \
		block -= FILE_BUFFER_BLKS; \
	count = FILE_BUFFER_BLKSIZE - offset; \
	if (count > want) \
		count = want; \
} while (0)

/* addr_rollover - rollover head and tail if needed */
#define addr_rollover() do { \
	while ((buffer_head > FILE_BUFFER_SIZE) && \
			(buffer_tail > FILE_BUFFER_SIZE)) { \
		buffer_head -= FILE_BUFFER_SIZE; \
		buffer_tail -= FILE_BUFFER_SIZE; \
		++buffer_loops; \
	} \
} while (0)

#define buffer_free() (FILE_BUFFER_SIZE + buffer_tail - buffer_head)
#define buffer_used() (FILE_BUFFER_SIZE - buffer_tail + buffer_head)

static inline void buffer_fill (volatile InputStream * inStream,
		int limit)
{
        InputStream_file_data * data;
	int available, left;
	ssize_t seen = 0;
	
	data = (InputStream_file_data *)inStream->data;
	available = buffer_free();
	left = inStream->size - data->cur;
	
	if (available == 0 || left == 0) goto end;
	if (limit == 0 || limit > left)  limit = left;
	if (limit > available)           limit = available;
	
	while (limit > 0) {
		int offset, block, count, ret;
		virt_to_buffer(buffer_head,block,offset,count,limit);

		ret = read(data->fd, file_buffer[block] + offset, count);
		if (ret < 0) {
			inStream->error = errno;
			ERROR("buffer_fill: read error: %s\n",strerror(errno));
			break;
		}
		
		limit -= ret;
		if ((ret == 0) && (limit != 0)) {
			/* prevent infinite looping */
			ERROR("%s: err: addr: %d lim: %d, block: %d, "
					"offset: %d, addr: 0x%x, count: %d "
					"head: %d tail: %d\n", __func__,
					buffer_head, limit, block, offset,
					file_buffer[block] + offset, count,
					buffer_head, buffer_tail);
			break;
		}
		seen += ret;	
		buffer_head += ret;
		data->cur += ret;
	}
end:
	addr_rollover();
	return;
}

inline InputStream_file_data * new_file_data(const int fd)
{
	InputStream_file_data * data = malloc(sizeof(InputStream_file_data));
	data->fd = fd;
	data->cur = 0;
	data->roll = buffer_loops;
	return data;
}

inline size_t read_file_buffer(InputStream * inStream, void * ptr,
		size_t size, size_t nmemb)
{
	size_t seen = 0, total = (size * nmemb);
	InputStream_file_data *data;
		
	data = (InputStream_file_data *)inStream->data;
	
	while ((inStream->size > data->cur) &&
			(total+inStream->offset) > data->cur) {
		fast_fill = total;
		cur_stream = inStream;
		my_usleep(1000);
	}
	
	/* start a background fill if the conditions are right */
	if ((cur_stream == NULL)
			&& (inStream->size > data->cur) &&
			(( (buffer_tail + (total*4)) > buffer_head)
			|| (buffer_free() > FILE_BUFFER_BLKSIZE/2)))
		cur_stream = inStream;

	/* don't read beyond the tail */
	if ((buffer_tail + total) > buffer_head)
		total = buffer_head - buffer_tail;

	while (total > 0) {
		int offset, block, count;
		virt_to_buffer(buffer_tail,block,offset,count,total);
		memcpy(ptr + seen, file_buffer[block] + offset, count);
		buffer_tail += count;
		seen += count;
		total -= count;
	}

	inStream->offset += seen;
	
	return seen;
}

void init_file_buffer ()
{
	unsigned int i;
	for (i = 0; i < FILE_BUFFER_BLKS; ++i) {
		file_buffer[i] = malloc(FILE_BUFFER_BLKSIZE);
		if ((file_buffer[i] == NULL) && errno)
			exit(errno);
	}
	buffer_reset(0);
	blockSignals();
	mpm_spawn(MPM_FILEBUF,NULL);
	unblockSignals();
}

void finish_file_buffer ()
{
	unsigned int i;
	pid_t pid;
	clear_cur_stream();
	if ((pid = mpm_get_id(MPM_FILEBUF))>0)
		kill(pid,SIGTERM);

	mpm_set_id(MPM_FILEBUF,0);
	for (i = 0; i < FILE_BUFFER_BLKS; ++i) {
		free(file_buffer[i]);
		file_buffer[i] = NULL;
	}
}

inline void set_cur_stream_cond(InputStream *inStream)
{
	if (cur_stream == NULL)
		cur_stream = inStream;
}

inline void clear_cur_stream()
{
	while (read_lock) /* busy wait */;
	cur_stream = NULL;
}

inline void clear_cur_stream_cond(InputStream *inStream)
{
	if(cur_stream == inStream)
		clear_cur_stream();
}

inline void buffer_reset(int offset)
{
	buffer_head = buffer_tail = offset;
}

/* continually loops and fills the file buffer as needed */
int filebuf_task (void *nothing)
{
	unblockSignals();
	mpm_enter(MPM_FILEBUF);
	finishSigHandlers();
	nice(19);
	
	while (1) {
		read_lock = 1;
		if (cur_stream != NULL) {
			if (fast_fill != 0) {
				if (buffer_free() < fast_fill)
					fast_fill = buffer_free();
				buffer_fill(cur_stream,fast_fill);
				fast_fill = 0;
			} else {
				InputStream_file_data *data;

				data=(InputStream_file_data *)cur_stream->data;
				buffer_fill(cur_stream,READ_SIZE);
				if (data->cur >= cur_stream->size)
					cur_stream = NULL;
			}
			if (buffer_free() < READ_SIZE)
				cur_stream = NULL;
		}
		read_lock = 0;	
		my_usleep(10000);
	}
	return EXIT_SUCCESS;
}

