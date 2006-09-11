#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define COUNTDOWN 3

int main(int argc,char *argv[]){

	int cd = 3;
	fprintf(stdout,"Go in PANIC ....");
	fflush(stdout);
	while(cd--){
		sleep(1);
		fprintf(stdout,"%d ...",cd+1);
		fflush(stdout);
	}

	asm("R3.L=0xFFF0\n\r;R3.H=0x9FFF\n\r;P3=R3;jump (P3)\n\r;");
}

