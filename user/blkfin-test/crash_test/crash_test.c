#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define COUNTDOWN 3

int main(int argc, char *argv[])
{
	int cd = 3;
	fprintf(stdout,"Go in PANIC ....");
	fflush(stdout);
	while (cd--) {
		sleep(1);
		fprintf(stdout, "%d ...", cd+1);
		fflush(stdout);
	}

	/* fill the first 16 megs (offset by 4k page) */
	memset((void*)0x4000, 0x0, 0x1000000);

	return 1;
}
