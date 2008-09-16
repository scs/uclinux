/*
 * ipod_io.c
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

#include <ipod/ipod_io.h>

int ipod_io_read(ipod_io io,void *data, size_t maxDataLen, size_t *dataRead) {
	return (io->read)(data,maxDataLen,dataRead,io->userData);
}

int ipod_io_write(ipod_io io,void *data, size_t dataLen, size_t *dataWritten) {
	return (io->write)(data,dataLen,dataWritten,io->userData);
}


int8_t ipod_io_getb(ipod_io io)
{
	int8_t b;
	size_t bytesRead;
	(void)(io->read)(&b,1,&bytesRead,io->userData);
	return b;
}

void ipod_io_putb(ipod_io io,int8_t b)
{
	size_t bytesWritten;
	(void)(io->write)(&b,1,&bytesWritten,io->userData);
}

uint8_t ipod_io_getub(ipod_io io)
{
	uint8_t b;
	size_t bytesRead;
	(io->read)(&b,1,&bytesRead,io->userData);
	return b;
}

void ipod_io_putub(ipod_io io,uint8_t b)
{
	size_t bytesWritten;
	(void)(io->write)(&b,1,&bytesWritten,io->userData);
}

int16_t ipod_io_getw(ipod_io io)
{
	uint8_t b1 = ipod_io_getub(io);
	return (ipod_io_getb(io)<<8)+b1;
}

void ipod_io_putw(ipod_io io,int16_t w)
{
	ipod_io_putub(io,w & 0xff);
	ipod_io_putub(io,w >> 8);
}

uint16_t ipod_io_getuw(ipod_io io)
{
	uint8_t b1 = ipod_io_getub(io);
	return (ipod_io_getub(io)<<8)+b1;
}

void ipod_io_putuw(ipod_io io,uint16_t w)
{
	ipod_io_putub(io,w & 0xff);
	ipod_io_putub(io,w >> 8);
}

int16_t ipod_io_getw_be(ipod_io io)
{
	int8_t b1 = ipod_io_getub(io);
	return ipod_io_getb(io)+(b1<<8);
}

void ipod_io_putw_be(ipod_io io,int16_t w)
{
	ipod_io_putub(io,w >> 8);
	ipod_io_putub(io,w & 0xff);
}

uint16_t ipod_io_getuw_be(ipod_io io)
{
	uint8_t b1 = ipod_io_getub(io);
	return ipod_io_getub(io)+(b1<<8);
}

void ipod_io_putuw_be(ipod_io io,uint16_t w)
{
	ipod_io_putub(io,w >> 8);
	ipod_io_putub(io,w & 0xff);
}

int32_t ipod_io_getl(ipod_io io)
{
	uint16_t w1 = ipod_io_getuw(io);
	return (ipod_io_getw(io)<<16)+w1;
}

void ipod_io_putl(ipod_io io,int32_t l)
{
	ipod_io_putuw(io,(unsigned short)(l & 0xffff));
	ipod_io_putuw(io,(unsigned short)(l>>16));
}

uint32_t ipod_io_getul(ipod_io io)
{
	uint16_t w1 = ipod_io_getuw(io);
	return (ipod_io_getuw(io)<<16)+w1;
}

void ipod_io_putul(ipod_io io,uint32_t l)
{
	ipod_io_putuw(io,l & 0xffff);
	ipod_io_putuw(io,l>>16);
}

int32_t ipod_io_getl_be(ipod_io io)
{
	int16_t w1 = ipod_io_getuw_be(io);
	return ipod_io_getw_be(io)+(w1<<16);
}

void ipod_io_putl_be(ipod_io io,int32_t l)
{
	ipod_io_putuw_be(io,(uint16_t)(l>>16));
	ipod_io_putuw_be(io,(uint16_t)(l & 0xffff));
}

uint32_t ipod_io_getul_be(ipod_io io)
{
	uint16_t w1 = ipod_io_getuw_be(io);
	return ipod_io_getuw_be(io)+(w1<<16);
}

void ipod_io_putul_be(ipod_io io,uint32_t l)
{
	ipod_io_putuw_be(io,l>>16);
	ipod_io_putuw_be(io,l & 0xffff);
}

float ipod_io_getf(ipod_io io)
{
	uint32_t f = ipod_io_getul(io);
	return *(float *)&f;
}

void ipod_io_putf(ipod_io io,float f)
{
	uint32_t t = *(uint32_t *)&f;
	ipod_io_putul(io,t); 
}

uint32_t ipod_io_get4cc(ipod_io io)
{
	uint32_t l;
	l = ipod_io_getub(io);
	l = (l<<8)+ipod_io_getub(io);
	l = (l<<8)+ipod_io_getub(io);
	l = (l<<8)+ipod_io_getub(io);
	return l;
}

void ipod_io_put4cc(ipod_io io,uint32_t l)
{
	ipod_io_putub(io,l>>24);
	ipod_io_putub(io,l>>16);
	ipod_io_putub(io,l>>8);
	ipod_io_putub(io,l);
}

uint32_t ipod_io_getul3(ipod_io io)
{
	uint32_t l;
	l = ipod_io_getub(io);
	l = (l<<8)+ipod_io_getub(io);
	l = (l<<8)+ipod_io_getub(io);
	return l;
}

void ipod_io_putul3(ipod_io io,uint32_t l)
{
	ipod_io_putub(io,l>>16);
	ipod_io_putub(io,l>>8);
	ipod_io_putub(io,l);
}

uint32_t ipod_io_getul_ss(ipod_io io) {
	uint32_t l;
	l = ipod_io_getub(io);
	l = (l<<7) + ipod_io_getub(io);
	l = (l<<7) + ipod_io_getub(io);
	l = (l<<7) + ipod_io_getub(io);
	return l;
}

void ipod_io_seek(ipod_io io,size_t offset) {
	(io->seek)(offset,io->userData);
}

size_t ipod_io_tell(ipod_io io) {
	size_t offset;
	(io->tell)(&offset,io->userData);
	return offset;
}

size_t ipod_io_length(ipod_io io) {
	size_t offset;
	(io->length)(&offset,io->userData);
	return offset;
}

void ipod_io_skip(ipod_io io,size_t count)
{
	ipod_io_seek(io,ipod_io_tell(io)+count);
}

void ipod_io_backpatch(ipod_io io,size_t mark)
{
	size_t here = ipod_io_tell(io);
	ipod_io_seek(io,mark+8);
	ipod_io_putul(io,here-mark);
	ipod_io_seek(io,here);

}

void ipod_io_get_simple_header(ipod_io io,size_t *h1,size_t *h2)
{
	size_t mark = ipod_io_tell(io);
	*h1 = ipod_io_getul(io)+mark-4;
	*h2 = ipod_io_getul(io)+mark-4;
}

size_t ipod_io_put_simple_header(ipod_io io,uint32_t tag,size_t size)
{
	size_t mark = ipod_io_tell(io);
	ipod_io_put4cc(io,tag);
	ipod_io_putul(io,size);
	ipod_io_putul(io,0);
	return mark;	
}

size_t ipod_io_get_list_header(ipod_io io)
{
	size_t mark = ipod_io_tell(io);
	return ipod_io_getul(io)+mark-4;	
}

size_t ipod_io_put_list_header(ipod_io io,uint32_t tag,size_t size)
{
	size_t mark = ipod_io_tell(io);
	ipod_io_put4cc(io,tag);
	ipod_io_putul(io,size);
	return mark;
}

void ipod_io_put_zeros(ipod_io io,unsigned int count)
{
	int i;
	for (i=0;i<count;i++)
		ipod_io_putul(io,0);
}

void ipod_io_put_pad(ipod_io io,size_t mark,size_t size)
{
	long delta = size-(ipod_io_tell(io)-mark);
	if (delta>0) {
		while (delta>4) {
			ipod_io_putul(io,0);
			delta -= 4;
		}
		while (delta) {
			ipod_io_putub(io,0);
			delta--;
		}
	}
}
