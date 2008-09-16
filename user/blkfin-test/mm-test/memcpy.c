#include <stdio.h>
#include <string.h>

#define FORCE_FLUSH

int ran[1<<16];
int A;

#ifdef FORCE_FLUSH
#define inv() ({int i; for (i=0;i<1<<14;i++)ran[i]=~ran[i]; })
#else
#define inv() ({int i; for (i=0;i<1<<14;i++)A+=ran[i]; })
#endif



typedef unsigned char uint8_t;
typedef unsigned uint32_t;
typedef unsigned long long uint64_t;

static inline uint64_t read_time(void)
{
    uint64_t t0;
    asm volatile ("%0=cycles; %H0=cycles2;" : "=d" (t0));
    return t0;
}

uint32_t *block1;
uint32_t *block2;



memcpy_c(uint32_t *d, uint32_t *s, int n)
{
    int i;
    n = n >> 2;
    for (i = 0; i<n;i++)
	*s++ = *d++;
}

memcpy_asm (uint32_t *d, uint32_t *s, int n)
{
    int i;
    n = (n >> 2)-1;
    asm ("r0=[%0++];\n\t"
	 "lsetup (0f,0f) lc0= %2;\n\t"
	 "0: [%1++]=r0 || r0=[%0++];\n\t"
	 "[%1++]=r0;\n\t"
	 : : "b" (s), "b" (d), "a" (n));
}

memcpy_bytes (uint8_t *d, uint8_t *s, int n)
{
    int i;

    for (i = 0; i<n;i++)
	*s++ = *d++;
}

#define PREFETCH(x) \
  asm volatile ("prefetch [%0];\n\t" : : "a" (x))

memcpy_prefetch (uint32_t *d, uint32_t *s, int n)
{
    uint8_t *pf0=d, *pf1=s;
    unsigned v;
    int i;
    int n8;
    PREFETCH (pf0);pf0+=32;
    PREFETCH (pf1);pf1+=32;

    n = n >> 2;
    n8 = n >> 3;

    for (i = 0; i<n8;i++) {
	PREFETCH (pf0);pf0+=32;
	PREFETCH (pf1);pf1+=32;
	*s++ = *d++;
	*s++ = *d++;
	*s++ = *d++;
	*s++ = *d++;
	*s++ = *d++;
	*s++ = *d++;
	*s++ = *d++;
	*s++ = *d++;
    }
}


int sum_c (unsigned *p, int n)
{
    int v = 0;
    int i;
    for (i=0;i<n;i++)
	v += *p++;
    return v;
}


int sum_asm (unsigned *p, int n)
{
    int v;
    asm ("r1=[%1++];                    \n\t"
	 "%0=0;                         \n\t"
	 "lsetup (0f,0f) lc0=%2;        \n\t"
	 "0: %0=%0+r1 (ns) || r1=[%1++];\n\t"
	 "%0=%0+r1 (ns);                \n\t"
	 : "=d" (v) : "a" (p), "a" (n-1) : "R1");
    return v;
}



struct {
    void *(*func)(void *d, void *s, int n);
    char *name;
    uint64_t t;
} s_memcpy[] = {
#define SM(x) { x, #x, 0 }
    SM(memcpy),
    SM(memcpy_c),
    SM(memcpy_asm),
    SM(memcpy_bytes),
    SM(memcpy_prefetch),
    { 0,0,0 },
};

struct {
    int (*func)(int *d, int n);
    char *name;
    uint64_t t;
} s_sum[] = {
#define SM(x) { x, #x, 0 }
    SM(sum_c),
    SM(sum_asm),
    { 0,0,0 },
};

#define CNT 100

main (int argc, char **argv)
{
    uint64_t t;
    int i;
    int j;
    int sz;
    int NN;
    int nbits = 14;
    int T0[16];
    int T1[16];

    if (argc > 1)
	nbits = atoi (argv[1]);

    NN = 1<<(nbits-2);
    sz = NN*sizeof(uint32_t);


    block1 = malloc (sz*2);
    block2 = block1+NN;

    printf ("nbits: %d NN: %d sz: %d %08x %08x\n", nbits, NN, sz, block1,block2);

    for (i=0;i<NN;i++)
	block1[i] = i;

    printf ("benchmarking memcpy\n");
    for (j=0;j<CNT;j++) {
	for (i=0;s_memcpy[i].func;i++) {
	    inv();
	    t = read_time ();
	    s_memcpy[i].func (block2, block1, sz);
	    t = read_time () - t;
	    s_memcpy[i].t += t;

	    if (memcmp (block2, block1, sz) != 0)
		printf ("%s: failed\n", s_memcpy[i].name);
	}
    }


    for (i=0;s_memcpy[i].name;i++)
	printf ("%20s:     %12.4f/CCLKS\n", s_memcpy[i].name, s_memcpy[i].t/(double)(NN*CNT));

    printf ("benchmarking sum\n");

    for (j=0;j<CNT;j++) {
	for (i=0;s_sum[i].func;i++) {
	    int v;
	    inv();
	    t = read_time ();
	    v = s_sum[i].func (block2, NN);
	    t = read_time () - t;
	    s_sum[i].t += t;
	}
    }

    for (i=0;s_sum[i].name;i++)
	printf ("%20s:     %12.4f/CCLKS\n", s_sum[i].name, s_sum[i].t/(double)(NN*CNT));

    printf ("benchmark single 32 bit word access from %08x\n", block2+7);
    for (i=0;i<16;i++)
    {
	unsigned t0,t1;
	inv();

	asm(
	    "r0=cycles;\n\t"
	    "%0=[%2++];\n\t"
	    "r1=cycles;\n\t"
	    "%0=[%2++];\n\t"
	    "%1=cycles;\n\t"
	    "%0=r1-r0 (ns);\n\t"
	    "%1=%1-r1 (ns);\n\t"
	    : "=d" (t0), "=d" (t1) : "p" (block2+28) : "R0","R1");
	T0[i] = t0;
	T1[i] = t1;
    }

    for (i=0;i<16;i++)
	printf ("get 1 line %d, %d\n", T0[i],T1[i]);

    free (block1);

}



