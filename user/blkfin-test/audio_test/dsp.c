/*
 *
 *    File:         dsp.c
 *    Rev:          $Id: dsp.c 841 2005-05-24 09:11:59Z sonicz $
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

#include "dsp.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>




int opendsp( const char* path, int channels, int samplerate, 
	     mode_t mode, size_t fragsize ){
  
  int fd;
  int fraglog, ioctlParam;
  audio_buf_info abi;
  
  fd = open( path, mode, 0);
  if( fd == -1 ) fprintf(stderr, "Could not open %s.\n", path );


  ioctlParam = AFMT_S16_LE;

  if( ioctl( fd, SNDCTL_DSP_SETFMT, &ioctlParam ) == -1 ) 
    fprintf(stderr, "SNDCTL_DSP_SETFMT: %s.\n", strerror(errno) );
  
  if( ioctlParam != AFMT_S16_LE ) 
    fprintf(stderr, "Failed to set DSP Format.\n");
  

  ioctlParam = channels;
  if( ioctl( fd, SNDCTL_DSP_CHANNELS, &ioctlParam ) == -1 ) 
    fprintf(stderr,  "SNDCTL_DSP_CHANNELS: %s\n", strerror(errno));
  
  if( ioctlParam != channels ) 
    fprintf(stderr, "Failed to set channels.\n");

  
  ioctlParam = samplerate;
  if( ioctl( fd, SNDCTL_DSP_SPEED, &ioctlParam ) == -1 )
    fprintf(stderr, "SNDCTL_DSP_SPEED: %s\n", strerror(errno));
  
  if( ioctlParam != samplerate ) 
    fprintf(stderr, "Failed to set samplerate.\n");
  
  fraglog=0;
  while( fragsize >>= 1 ) ++fraglog;

  ioctlParam = 0x7fff0000 | fraglog;
  if( ioctl(fd, SNDCTL_DSP_SETFRAGMENT, &ioctlParam) == -1 )
    fprintf(stderr, "SNDCTL_DSP_SETFRAGMENT:%s.\n", strerror(errno));


  if(mode == O_RDONLY){
     if( ioctl( fd, SNDCTL_DSP_GETISPACE, &abi ) )
        fprintf(stderr, "SNDCTL_DSP_GETISPACE:%s.\n", strerror(errno));
  } else {
     if( ioctl( fd, SNDCTL_DSP_GETOSPACE, &abi ) )
       fprintf(stderr, "SNDCTL_DSP_GETOSPACE:%s.\n", strerror(errno));
  }

  fprintf(stderr, "dsp: fragments: %d, fragstotal: %d, fragsize: %d, bytes: %d\n", 
	  abi.fragments, abi.fragstotal, abi.fragsize, abi.bytes);


  return fd;
  
}



int opendsp_read(  int channels, int samplerate,  const char* path, size_t fragsize ){
  return opendsp(path, channels, samplerate, O_RDONLY, fragsize);
}

int opendsp_write( int channels, int samplerate, const char* path,  size_t fragsize ){
  return opendsp(path, channels, samplerate,  O_WRONLY, fragsize);
}

    

void silence(int dsp){

  int i;
  audio_buf_info abi;
  char buf[1024];

  if( ioctl( dsp, SNDCTL_DSP_GETOSPACE, &abi ) )
    fprintf(stderr, "SNDCTL_DSP_GETOSPACE:%s.\n", strerror(errno));
  
  for( i=0; i<1024; i++) buf[i]=0;
  for( i=0; i<abi.fragstotal*abi.fragsize; i+=1024 )
    write(dsp, buf,1024);

  return;

}    
    
