/* The shadow of the original with only common prototypes now. */
#include <stdio.h>
#include <sys/types.h>

/* get definition of HZ */
#include <asm/param.h>

/* get page info */
#include <asm/page.h>

char *wchan(unsigned long);
char *find_func(unsigned long address);
void *xcalloc(void *pointer, int size);
void *xmalloc(unsigned int size);
void *xrealloc(void *oldp, unsigned int size);
       
int   mult_lvl_cmp(void* a, void* b);
int   node_mult_lvl_cmp(void* a, void* b);
void  dump_keys(void);
       
char *user_from_uid(int uid);

int   open_sysmap(void);
int   open_psdb(void);
void  close_psdb(void);
void  make_fnctbl(void);

unsigned print_str    (FILE* file, char *s, unsigned max);
unsigned print_strlist(FILE* file, char **strs, char* sep, unsigned max);
unsigned snprint_strlist(char *buf, int max, char **strs, char *sep);
