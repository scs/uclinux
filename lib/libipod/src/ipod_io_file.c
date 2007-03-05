/*
 * ipod_io_file.c
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <ipod/ipod_io_file.h>
#include <ipod/ipod_memory.h>
#include <sys/stat.h>

int ipod_io_file_read(void *data, size_t maxDataLen, size_t *dataRead,void *userData)
{
	*dataRead = fread(data,1,maxDataLen,(FILE *)userData);
	return 0;
}

int ipod_io_file_write(void *data, size_t dataLen,size_t *dataWritten,void *userData)
{
	*dataWritten = fwrite(data,1,dataLen,(FILE *)userData);
	return 0;
}

int ipod_io_file_tell(size_t *offset,void *userData)
{
	*offset = ftell((FILE *)userData);
	return 0;
}

int ipod_io_file_seek(size_t offset,void *userData)
{
	return fseek((FILE *)userData,offset,SEEK_SET);
}

int ipod_io_file_length(size_t *offset,void *userData)
{
	struct stat s;
	fstat(fileno((FILE *)userData),&s);
	*offset = s.st_size;
	return 0;
}

ipod_io ipod_io_file_new(FILE *file)
{
	ipod_io io = (ipod_io)ipod_memory_alloc(sizeof(ipod_io_struct));
	io->userData = (void *)file;
	io->read = ipod_io_file_read;
	io->write = ipod_io_file_write;
	io->tell = ipod_io_file_tell;
	io->seek = ipod_io_file_seek;
	io->length = ipod_io_file_length;
	return io;
}

void ipod_io_file_free(ipod_io io)
{
	if (io)
		ipod_memory_free(io);
}

