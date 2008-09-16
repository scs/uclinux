#ifndef FPS
#define FPS

/*
  Frames-per-second timer
  author:  Scott Scriven (water@xyzz.org)
*/

#include <time.h>
#include <stdio.h>


unsigned int frames = 0;
clock_t begin, fini;

void FpsStart();
void FpsEnd();
void ShowFps();
int Fps();


void FpsStart()
{
  begin = clock();
}

void FpsEnd()
{
  fini = clock();
}


void ShowFps()
{
  if(fini - begin > 0)
  {
    printf("\nFrames : %i", frames);
    printf("\nSeconds: %f", (float)(fini-begin)/CLOCKS_PER_SEC);
    printf("\nFPS    : %f\n", (float)frames/(float)(fini-begin)*CLOCKS_PER_SEC);
  }
}

int Fps()
{
  int rate;

  fini = clock();

  if(fini-begin <= 0) return 0;
  rate = (int)((float)frames / (float)(fini-begin)*CLOCKS_PER_SEC);

  return rate;
}

#endif
