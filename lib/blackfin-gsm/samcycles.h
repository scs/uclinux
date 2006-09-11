/*
  samcycles.h
  David Rowe 
  16 May 2006

  Simple library to sample and report on CPU cycles.  The overhead
  per sample is a write to an array, no function calls or printfs()
  at run time reqd.
*/

/* user-supplier cycles function */

#ifndef __SAMCYCLES__
#define __SAMCYCLES__

unsigned int samcycles_cycles();

typedef struct {
  char         *label;
  unsigned int  cycles;
} samcycles_sample;

extern samcycles_sample samcycles_samples[];
extern int samcycles_index;

#define SAMCYCLES(lab)                                            \
{                                                                 \
  unsigned int sam;                                               \
                                                                  \
  __asm__ __volatile__                                            \
  (                                                               \
    "%0 = CYCLES;\n\t"                                            \
  : "=&d" (sam)                                                   \
  :                                                               \
  : "R1"                                                          \
  );                                                              \
  samcycles_samples[samcycles_index].label = lab;                 \
  samcycles_samples[samcycles_index].cycles = sam;                \
  samcycles_index++;                                              \
}

void samcycles_dump();

#endif
