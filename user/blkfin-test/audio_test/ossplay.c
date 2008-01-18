/*
 * File:         ossplay.c 
 * Description:  test capture  for ADI 1836 
 * Rev:          $Id: ossplay.c 841 2005-05-24 09:11:59Z sonicz $
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Author:       Luuk van Dijk
 * mail:         blackfin@mdnmttr.nl
 * 
 * Copyright (C) 2004 Luuk van Dijk, Mind over Matter B.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "dsp.h"


char* argv0;

void crash(char* msg){
  fprintf(stderr, "%s:%s:%s\n", argv0, msg, strerror(errno) );
  exit(1);
}

void usage(void){
  fprintf(stderr, "usage:%s -c channels -f fragsize -s samplefreq -t time\n", argv0 );
  exit(1);
}

char buf[81920];

int main( int argc, char* argv[] ){

  const char* dsppath = "/dev/dsp";

  int fragcount = 10;
  int fragsize  = 8192;
  int samplefreq  = 48000;
  int channels = 2;

  int inf;
  int dac;
  int c;

  argv0= argv[0];

  fprintf(stderr, "%s: $Id: ossplay.c 841 2005-05-24 09:11:59Z sonicz $\n", argv0);

  while( (c = getopt(argc, argv, "c:f:s:t:")) != -1 ) {
    switch (c) {
    case 'c': channels   = atoi(optarg); break;
    case 'f': fragsize   = atoi(optarg); break;
    case 's': samplefreq = atoi(optarg); break;
    case 't': fragcount  = atoi(optarg); break;
    default: usage();
    }
  }

  argc -= optind;
  argv += optind;

  if( !argc ) usage();

  fragcount *= samplefreq;
  fragcount /= fragsize;

  fprintf( stderr, "%s: channels: %d fragsize: %d samplefreq: %d fragcount :%d\n",
	   argv0, channels, fragsize, samplefreq, fragcount );



  if( (dac = opendsp_write(  channels, samplefreq, dsppath, fragsize )) == -1 ) 
    crash( "open(write)" );
  
  if( (inf = open( argv[0], O_RDONLY) ) == -1 ) 
    crash( "open(inf)" );
  
  while(1){
    while(1){
      if( read(  inf, buf, fragsize ) != fragsize ) break;
      if( write( dac, buf, fragsize ) != fragsize ) crash( "write" );
    }
    lseek(inf, 0, SEEK_SET);
  }
  
  close(dac);
  close(inf);

  return 0;
}

