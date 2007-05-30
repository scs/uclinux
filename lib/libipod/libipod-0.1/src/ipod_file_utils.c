/*
 * ipod_file_utils.c
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

#include <ipod/ipod_file_utils.h>
#include <ipod/ipod_error.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

int ipod_directory_exists(const char *path)
{
	DIR *dir = opendir(path);
	if (dir) {
		closedir(dir);
		return 1;
	}
	return 0;
}
 
int ipod_file_exists(const char *path)
{
	FILE *f = fopen(path,"rb");
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
}

void ipod_delete_file(const char *path)
{
	remove(path);
}

#define COPY_BUFFER_LEN (16*1024)

static void ipod_copy_file_contents(FILE *src,FILE *dst,size_t size,ipod_file_transfer_func callback,void *userData)
{
	unsigned long progress = 0;
	char *buffer = (char *)ipod_memory_alloc(COPY_BUFFER_LEN);
	if (callback)
		(callback)(progress,size,userData);
	for(;;) {
		unsigned long bytesRead,bytesWritten;
		bytesRead = fread(buffer,1,COPY_BUFFER_LEN,src);
		if (bytesRead==0)
			break;
		bytesWritten = fwrite(buffer,1,bytesRead,dst);
		// XXX DSM probably should check that bytesWritten==bytesRead
		progress += bytesWritten;
		if (callback)
			(callback)(progress,size,userData);
	}
	ipod_memory_free(buffer);
}

int ipod_copy_file(const char *srcFile, const char *dstFile,ipod_file_transfer_func callback,void *userData)
{

	struct stat s;
	if (!stat(srcFile,&s)) {
		FILE *src = fopen(srcFile,"rb");
		if (src) {
			FILE* dst = fopen(dstFile,"wb");
			if (dst) {
				ipod_copy_file_contents(src,dst,s.st_size,callback,userData);
				fclose(dst);
				fclose(src);
				return 0;
			} else {
				ipod_error("ipod_copy_file(): Can't write %s\n",dstFile);
			}
			fclose(src);
		} else {
			ipod_error("ipod_copy_file(): Can't open %s\n",srcFile);
		}
	} else {
		ipod_error("ipod_copy_file(): Can't stat() %s\n",srcFile);
	}
	return -1;
}

const char *ipod_extension_of(const char *path,const char *def)
{
	char *dot = strrchr(path,'.');
	if (dot) return dot;
	return def;
}

const char *ipod_file_name_of(const char *path)
{
	char *slash = strrchr(path,'/');
	if (slash) return slash;
	return path;
}
