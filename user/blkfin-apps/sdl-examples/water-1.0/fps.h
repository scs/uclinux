#ifndef FPS
#define FPS

/*
  Frames-per-second timer
  author:  Scott Scriven (water@xyzz.org)
*/

#include <time.h>


extern unsigned int frames;
extern clock_t begin, fini;

extern void FpsStart();
extern void FpsEnd();
extern void ShowFps();
extern int Fps();


#endif
