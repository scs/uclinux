#ifndef DATATYPE

#define DATATYPE

#include <stdlib.h>

/*
  Miscellaneous stuff I use in DJGPP...
  author:  Scott Scriven (water@xyzz.org)
*/


#ifdef __cplusplus
extern "C" {
#endif

#define byte	unsigned char
#define sbyte	signed char
#define word    unsigned short
#define sword   signed short
#define dword	unsigned long
#define sdword	signed long
#define qword   unsigned long long int
#define sqword  signed long long int

#define bLO(n)  (n     & 0x0F)
#define bHI(n) ((n>>4) & 0x0F)
#define wLO(n)  (n     & 0x00Ff)
#define wHI(n) ((n>>8) & 0x00Ff)
#define lLO(n)  (n      & 0x0000FFff)
#define lHI(n) ((n>>16) & 0x0000FFff)
#define qLO(n)  (n      & 0x00000000FFFFffff)
#define qHI(n) ((n>>32) & 0x00000000FFFFffff)


#define randomize(); srand(time(NULL));


#ifdef __cplusplus
}
#endif

#endif
