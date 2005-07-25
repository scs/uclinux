/*	setenv.c
 *	OZH, 2001
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <asm/uCbootstrap.h>

_bsc1 (int, setbenv, char *, a)

int main(int argc, char *argv[]) 
{
    char buf[128];

    if	(argc<2) {
	printf("usage: %s varname value\n       %s varname\n",argv[0],argv[0]);
	return; 
	}
    strcpy(buf, argv[1]);
    if	(argc>2) {
	strcat(buf, "=");
	strcat(buf, argv[2]); 
	}
    setbenv(buf);
    return (0); 
}
