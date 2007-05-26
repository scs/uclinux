/* the Music Player Daemon (MPD)
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
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

#include "inputStream_file.h"
#include "file_buffer.h"
#include "mpm.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline int inputStream_fileSeek(InputStream * inStream, long offset,
		int whence)
{
        InputStream_file_data * data = (InputStream_file_data *)inStream->data;
	data->cur = inStream->offset = lseek(data->fd, offset, whence);
	if ((inStream->offset < 0) && errno) {	
		inStream->error = errno;
		return -1;
	}

	return 0;
}

static int inputStream_buffered_file_seek(InputStream * inStream, long offset,
		int whence)
{
	buffer_reset(0);
	return inputStream_fileSeek(inStream, offset, whence);
}

static size_t inputStream_fileRead(InputStream * inStream, void * ptr,
		size_t size, size_t nmemb)
{
        InputStream_file_data * data = (InputStream_file_data *)inStream->data;
	size_t seen = read(data->fd, ptr, (size * nmemb));
        
	if (seen < 0) {
                inStream->error = errno;
		DEBUG("inputStream_fileRead: error reading: %s\n",  
				strerror(inStream->error));
        }
	
	inStream->offset += seen;
	
	return seen;
}

static inline int inputStream_fileClose(InputStream * inStream)
{
        InputStream_file_data * data = (InputStream_file_data *)inStream->data;
	if (close(data->fd) < 0)
		inStream->error = errno;

	return 0;
}

static int inputStream_buffered_file_close(InputStream * inStream)
{
        InputStream_file_data * data = (InputStream_file_data *)inStream->data;
	clear_cur_stream_cond(inStream);
	free(data);
	data = NULL;
	return inputStream_fileClose(inStream);
}

static int inputStream_fileAtEOF(InputStream * inStream)
{
	if(inStream->offset >= inStream->size)
		return 1;
        
	return 0;
}

static int inputStream_fileBuffer(InputStream * inStream)
{
        return 0;
}

int inputStream_fileOpen(InputStream * inStream, char * filename) {
	int fd = open(filename,O_RDONLY|O_STREAMING);
	if (fd <= 0) {
		inStream->error = errno;
		return -1;
	}
        inStream->seekable = 1;

	inStream->size = lseek(fd,0,SEEK_END);
	inStream->offset = lseek(fd,0,SEEK_SET);

	inStream->data = new_file_data(fd);
	inStream->bufferFunc = inputStream_fileBuffer;
	inStream->atEOFFunc = inputStream_fileAtEOF;
	
	if (mpm_get_id(MPM_FILEBUF)) {
		inStream->seekFunc = inputStream_buffered_file_seek;
		inStream->readFunc = read_file_buffer;
		inStream->closeFunc = inputStream_buffered_file_close;
	} else {
		inStream->seekFunc = inputStream_fileSeek;
		inStream->readFunc = inputStream_fileRead;
		inStream->closeFunc = inputStream_fileClose;
	}
	
	return 0;
}

void inputStream_initFile() { }


