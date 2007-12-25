#ifndef FIXSIN
#define FIXSIN

/*
  16.16 fixed-point sine lookup tables...
  author:  Scott Scriven (water@xyzz.org)
*/



#define FSINMAX 2047
#define SINFIX 16
#define FSINBITS 16


#include <math.h>

#ifndef PI
#define PI 3.14159265358979323846
#endif

int FSinTab[2048];
int FCosTab[2048];

int FSin(int angle);
int FCos(int angle);

void FCreateSines();




int FSin(int angle)
{
  return FSinTab[angle&FSINMAX];
}

int FCos(int angle)
{
  return FCosTab[angle&FSINMAX];
}

void FCreateSines()
{
  int i;
  double angle;


  for(i=0; i<2048; i++)
  {
    angle = (float)i * (PI/1024.0);

    FSinTab[i] = (int)(sin(angle) * (float)0x10000);
    FCosTab[i] = (int)(cos(angle) * (float)0x10000);
  }
}


#endif
