/*
 *
 *    File:         dsp.hh
 *    Rev:          $Id: dsp.h 841 2005-05-24 09:11:59Z sonicz $
 *    Created:      Tue Jun 24 23:42:38 CEST 2003
 *    Author:       Luuk van Dijk
 *    mail:         lvd@mndmttr.nl
 *    Description:  open /dev/dsp for reading/writing
 *
 *   Copyright (C) 2003 Luuk van Dijk/Mind over Matter
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 */

#ifndef __MNDMTTR_DSP_H__
#define __MNDMTTR_DSP_H__

#include <stdio.h>

#define DEFAULT_DSP_PATH "/dev/dsp"


#if 0
typedef void (*logfunc_t)(int, const char*, ...);
#endif
  
int opendsp_read(  int channels, int samplerate,  const char* path, 
		   size_t fragsize);
     
int opendsp_write( int channels, int samplerate, const char* path, 
		   size_t fragsize);

void silence(int dsp);

#endif
