#include <stdio.h>

#define FORCE_FLUSH
#define ALIGN __attribute__ ((aligned(32)))

int ran[1<<16] ALIGN;
int A;

#ifdef FORCE_FLUSH
#define inv() ({int _; for (_=0;_<1<<14;_++)ran[_]=~ran[_]; })
#else
#define inv() ({int _; for (_=0;_<1<<14;_++)A+=ran[_]; })
#endif

main()
{
    int i;
    int T[16];
    int T0[16];
    int T1[16];
    int T2[16];
    int T3[16];
    int T4[16];
    int T5[16];


    printf ("benchmark single 32 bit word access from %08x\n", ran);
    for (i=0;i<16;i++)
    {
	inv();

	asm("P0=%6;         \n\t"
	    "%0=cycles;     \n\t"
	    "r0=w[p0++];     \n\t"
	    "%1=cycles;     \n\t"
	    "r0=w[p0++];     \n\t"
	    "%2=cycles;     \n\t"
	    "r0=w[p0++];     \n\t"
	    "%3=cycles;     \n\t"
	    "r0=w[p0++];     \n\t"
	    "%4=cycles;     \n\t"
	    "r0=w[p0++];     \n\t"
	    "%5=cycles;     \n\t"
	    "r0=w[p0++];     \n\t"
	    "r1=cycles;     \n\t"

	    "%0=%1-%0 (ns); \n\t"
	    "%1=%2-%1 (ns); \n\t"
	    "%2=%3-%2 (ns); \n\t"
	    "%3=%4-%3 (ns); \n\t"
	    "%4=%5-%4 (ns); \n\t"
	    "%5=r1-%5 (ns); \n\t"
	    : "=d" (T0[i]), "=d" (T1[i]), "=d" (T2[i]), "=d" (T3[i]), "=d" (T4[i]), "=d" (T5[i])
	    : "p" (ran) : "R0","R1","P0");
    }

    for (i=0;i<16;i++)
	printf ("get 1 line %d, %d, %d, %d, %d, %d ...\n", T0[i],T1[i],T2[i],T3[i],T4[i],T5[i]);

    memset (T,0,sizeof(T));
    for (i=0;i<16;i++) {
	inv();
	asm ("P0=%1;     \n\t"
	     "%0=cycles; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=[p0++]; \n\t"
	     "r0=cycles; \n\t"
	     "%0=r0-%0;  \n\t"
	     : "=d" (T[i]) : "p" (ran) : "R0","P0");
    }

    for (i=0;i<16;i++)
	printf ("cline read %d\n", T[i]);


    memset (T,0,sizeof(T));
    for (i=0;i<16;i++) {
	inv();
	asm ("P0=%1;                 \n\t"
	     "%0=cycles;             \n\t"
	     "lsetup (0f,0f) lc0=%2; \n\t"
	     "0: r0=[p0++];          \n\t"
	     "r0=cycles;             \n\t"
	     "%0=r0-%0 (ns);         \n\t"
	     : "=d" (T[i]) : "a" (ran), "a" (1024>>2) : "R0", "P0", "LC0");
    }

    for (i=0;i<16;i++)
	printf ("1K loads %d\n", T[i]);

    {
	unsigned *B = malloc (1024*1024);
	asm ("P0=%1;                 \n\t"
	     "%0=cycles;             \n\t"
	     "lsetup (0f,0f) lc0=%2; \n\t"
	     "0: r0=[p0++];          \n\t"
	     "r0=cycles;             \n\t"
	     "%0=r0-%0 (ns);         \n\t"
	     : "=d" (T[i]) : "a" (B), "a" (1024*1024>>2) : "R0", "P0", "LC0");

    }

}
