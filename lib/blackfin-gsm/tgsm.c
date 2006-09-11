/*
  tgsm.c
  David Rowe 6 June 2006

  Test program for GSM codec on the Blackfin.
*/

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "gsm/inc/gsm.h"
#include "samcycles.h"

#define N 160
#define M 33

inline unsigned int cycles() {
  int ret;

   __asm__ __volatile__ 
   (
   "%0 = CYCLES;\n\t"
   : "=&d" (ret)
   : 
   : "R1"
   );

   return ret;
}

int main(int argc, char *argv[]) {
  gsm    genc,gdec;
  FILE  *fin;
  FILE  *fout;
  short  buf_in[N];
  short  buf_out[N];
  char   bits[M];
  float  s,e;
  int    i, frames;
  unsigned int before;
  unsigned int enc_cycles, dec_cycles;

  if (argc != 3) {
    printf("usage: %s InputFile OutputFile\n", argv[0]);
    exit(0);
  }

  fin = fopen(argv[1],"rb");
  if (fin == NULL) {
    printf("Error opening %s\n",argv[1]);
    exit(0);
  }

  fout = fopen(argv[2],"wb");
  if (fin == NULL) {
    printf("Error opening %s\n",argv[2]);
    exit(0);
  }

  genc = gsm_create();
  gdec = gsm_create();
  s = e = 0.0;
  enc_cycles = dec_cycles = 0;
  frames = 0;

  while(fread(buf_in, sizeof(short), N, fin) == N) {
    before = cycles();
    gsm_encode(genc, buf_in, (gsm_byte*)bits);
    enc_cycles += (cycles()-before)/1000;

    before = cycles();
    gsm_decode(gdec, (gsm_byte*)bits, buf_out);
    dec_cycles += (cycles()-before)/1000;

    /* this dumps a profile of frame 10 */

    if (frames == 10) {
      samcycles_dump();
    }
    else
      samcycles_index	= 0; /* prevent overflow of samcycles array */

    for(i=0; i<N; i++) {
      s += pow((float)buf_in[i], 2.0);
      e += pow((float)buf_in[i]-(float)buf_out[i], 2.0);
    }
    fwrite(buf_out, sizeof(short), N, fout);
    frames++;
  }

  printf("SNR = %3.4f dB enc %d dec %d k cycles/frame\n", 
	 10*log10(s/e), enc_cycles/frames, dec_cycles/frames);

  fclose(fin);
  fclose(fout);
  gsm_destroy(genc);
  gsm_destroy(gdec);

  return 0;
}
