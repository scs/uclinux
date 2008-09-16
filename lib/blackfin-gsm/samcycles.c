/*
  samcycles.c
  David Rowe 
  16 May 2006

  Simple library to sample and report on CPU cycles.
*/

#include <stdio.h>
#include <samcycles.h>

#define MAX_SAMPLES 100

samcycles_sample samcycles_samples[MAX_SAMPLES];

int samcycles_index = 0;

/* prints results and resets index for next run */

void samcycles_dump() {
  int              i;
  samcycles_sample sam;
  unsigned int     prev_cycles;

  prev_cycles = samcycles_samples[0].cycles;

  for(i=0; i<samcycles_index; i++) {
    sam = samcycles_samples[i];
    printf("%s, %u\n", 
	   sam.label, sam.cycles-prev_cycles);
    prev_cycles = sam.cycles;
  }

  printf("TOTAL, %u\n", 
	 samcycles_samples[samcycles_index-1].cycles -
	 samcycles_samples[0].cycles);
  samcycles_index = 0;
}

