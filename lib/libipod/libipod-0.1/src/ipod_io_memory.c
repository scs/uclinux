/*
 * ipod_io_memory.c
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

#include <ipod/ipod_io_memory.h>
#include <ipod/ipod_memory.h>

#define MEMORY_CHUNK_SIZE 8192
#define IPOD_IO_MEMORY_MAGIC 0x05675309

typedef struct  {
	long magic; // indicator that this is a valid structure
	int owned; // flag to indicate that we allocated the memory
	char *data; // pointer to character array
	size_t memorySize; // current allocated memory size
	size_t dataSize; // current data length
	size_t offset; // where the "file pointer" is
} ipod_io_memory_struct, *ipod_io_memory;

static void ensureMemory(ipod_io_memory m,size_t size)
{
	if (m->memorySize<size) {
		size_t newsize = ((size+MEMORY_CHUNK_SIZE-1)/MEMORY_CHUNK_SIZE)*MEMORY_CHUNK_SIZE;
		m->data = (char *)ipod_memory_realloc(m->data,newsize);
		m->memorySize = newsize;
	}
}

size_t min(size_t a, size_t b) {
	if (a<b) return a;
	return b;
}

int ipod_io_memory_read(void *data, size_t maxDataLen, size_t *dataRead,void *userData)
{
	ipod_io_memory m = (ipod_io_memory)userData;
	*dataRead = 0;
	if (m->magic==IPOD_IO_MEMORY_MAGIC) {
		*dataRead = min(maxDataLen,m->dataSize-m->offset);
		memcpy(data,m->data,*dataRead);
		m->offset += *dataRead;
	}
	return 0;
}

int ipod_io_memory_write(void *data, size_t dataLen,size_t *dataWritten,void *userData)
{
	ipod_io_memory m = (ipod_io_memory)userData;
	*dataWritten = 0;
	if (m->magic==IPOD_IO_MEMORY_MAGIC) {
		ensureMemory(m,m->offset+dataLen);
		memcpy(m->data+m->offset,data,dataLen);
		m->offset += dataLen;
		if (m->offset>m->dataSize)
			m->dataSize = m->offset;
		*dataWritten = dataLen;
	}
	return 0;
}

int ipod_io_memory_tell(size_t *offset,void *userData)
{
	ipod_io_memory m = (ipod_io_memory)userData;
	*offset = 0;
	if (m->magic==IPOD_IO_MEMORY_MAGIC)
		*offset =  m->offset;
	return 0;
}

int ipod_io_memory_seek(size_t offset,void *userData)
{
	ipod_io_memory m = (ipod_io_memory)userData;
	if (m->magic==IPOD_IO_MEMORY_MAGIC) {
		m->offset = offset;
		ensureMemory(m,m->offset);
		if (m->offset>m->dataSize);
			m->dataSize = m->offset;
	}
	return 0;
}

int ipod_io_memory_length(size_t *offset,void *userData)
{
	ipod_io_memory m = (ipod_io_memory)userData;
	*offset = 0;
	if (m->magic==IPOD_IO_MEMORY_MAGIC)
		*offset =  m->dataSize;
	return 0;
}

static ipod_io ipod_io_memory_new_basic(void)
{
	ipod_io_memory m;
	ipod_io io = (ipod_io)ipod_memory_alloc(sizeof(ipod_io_struct));
	m = (ipod_io_memory)ipod_memory_alloc(sizeof(ipod_io_memory_struct));
	io->userData = (void *)m;
	io->read = ipod_io_memory_read;
	io->write = ipod_io_memory_write;
	io->tell = ipod_io_memory_tell;
	io->seek = ipod_io_memory_seek;
	io->length = ipod_io_memory_length;
	m->magic = IPOD_IO_MEMORY_MAGIC;
	m->data = NULL;
	m->dataSize = 0;
	m->offset = 0;
	m->owned = 0;
	return io;
}

ipod_io ipod_io_memory_new(void)
{
	ipod_io_memory m;
	ipod_io io = ipod_io_memory_new_basic();
	m = (ipod_io_memory)(io->userData);
	m->data = (char *)ipod_memory_alloc(0);
	m->owned = 1;
	return io;
}

ipod_io ipod_io_memory_new_from_memory(char *data,size_t dataLen)
{
	ipod_io_memory m;
	ipod_io io = ipod_io_memory_new_basic();
	m = (ipod_io_memory)(io->userData);
	m->data = data;
	m->dataSize = dataLen;
	return io;
}

void ipod_io_memory_free(ipod_io io)
{
	if (io) {
		ipod_io_memory m = (ipod_io_memory)(io->userData);
		if (m && m->magic == IPOD_IO_MEMORY_MAGIC) {
			if (m->owned)
				ipod_memory_free(m->data);
			ipod_memory_free(m);
		}
		ipod_memory_free(io);
	}
}

size_t ipod_io_memory_size(ipod_io io)
{
	ipod_io_memory m = (ipod_io_memory)(io->userData);
	if (m && m->magic == IPOD_IO_MEMORY_MAGIC)
		return m->dataSize;
	return 0;
}

char *ipod_io_memory_data(ipod_io io)
{
	ipod_io_memory m = (ipod_io_memory)(io->userData);
	if (m && m->magic == IPOD_IO_MEMORY_MAGIC)
		return m->data;
	return NULL;
}
