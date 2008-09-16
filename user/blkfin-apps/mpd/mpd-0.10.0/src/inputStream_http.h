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

#ifndef INPUT_STREAM_HTTP_H
#define INPUT_STREAM_HTTP_H

#include "../config.h"
#include "inputStream.h"

#ifdef HAVE_HTTP_INPUT

void inputStream_initHttp();

int inputStream_httpOpen(InputStream * inStream, char * filename);

int inputStream_httpSeek(InputStream * inStream, long offset, int whence);

size_t inputStream_httpRead(InputStream * inStream, void * ptr, size_t size, 
		size_t nmemb);

int inputStream_httpClose(InputStream * inStream);

int inputStream_httpAtEOF(InputStream * inStream);

int inputStream_httpBuffer(InputStream * inStream);

#else /* !HAVE_HTTP_INPUT */

static inline void inputStream_initHttp() { }

static inline int inputStream_httpOpen(InputStream *inStream, char *filename) { return 1; }

#endif /* !HAVE_HTTP_INPUT */
#endif
