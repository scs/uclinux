#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF 4096

int main ()
{
        int i;
        unsigned long *p,*j;

        j = p = malloc(BUF*4);

        for(i=0; i < BUF; i++){
                *p = 0;
                p++;
        }

        p = j;

        for(i=0; i< BUF; i++){
                *p = (int)malloc(1024*4);
                if (!(*p))
                        break;
                p++;
        }

        p = j;
        for(i=0; i< BUF; i++){
                free ((void *)(*p));
                p++;
        }

        free (j);
	printf("mkfragment success\n");
}
