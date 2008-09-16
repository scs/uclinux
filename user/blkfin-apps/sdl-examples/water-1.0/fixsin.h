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


extern int FSinTab[2048];
extern int FCosTab[2048];

extern int FSin(int angle);
extern int FCos(int angle);

extern void FCreateSines();





#endif
