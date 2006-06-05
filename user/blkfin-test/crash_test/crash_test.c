#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define COUNTDOWN 3

int main(int argc,char *argv[]){

	char *p_o = (char *) 0x30000000;
	char *p_i = (char *) 0x40000000;
	int cd = COUNTDOWN;
	
	fprintf(stdout,"Go in PANIC ....");
	fflush(stdout);
	while(cd--){
		sleep(1);
		fprintf(stdout,"%d ...",cd+1);
		fflush(stdout);
	}
	while(1){
		*p_o++ = *p_i++;
		sleep(1);
	}
}

