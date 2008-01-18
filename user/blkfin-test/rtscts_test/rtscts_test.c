#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>

/*
 * SW4 status should be set to:
 * 	pin1 - ON
 *	pin2 - ON
 *	pin3 - ON
 *	pin4 - OFF
 */

int main(int argc, char* argv[])
{
	int rtscts = TIOCM_RTS;
	int f;
	char devname[30]="/dev/";
       
	if(argc<3 || argv[2][0]!='-' || 
		!(argv[2][1]=='e' || argv[2][1]=='d' || argv[2][1]=='t' || argv[2][1]=='s')) {
		printf("Usage: %s <ttyBFx> <-e|-d|-t|-s>\n\t-e Enable RTS\n\t-d Disable RTS\n\t-t Test RTS\n\t-s Status of RTS/CTS\n", argv[0]);
		return 0;
	}
	
	strncat(devname, argv[1], 25);
	f = open(devname, O_RDWR);
	if(f<0) {
		printf("Fail to open %s\n", devname);
		return 0;
	}

	switch(argv[2][1]) {
	case 'e':
		ioctl(f, TIOCMBIS, &rtscts);
		printf("RTS on %s is enabled.\n", devname);
		break;
	case 'd':
		ioctl(f, TIOCMBIC, &rtscts);
		printf("RTS on %s is disabled.\n", devname);
		break;
	case 't':
		printf("Disable RTS on %s for 5 seconds. \nIf you hit any keys, you won't see them.\n", devname);
		ioctl(f, TIOCMBIC, &rtscts);
	
		sleep(5);
	
		ioctl(f, TIOCMBIS, &rtscts);
		printf("\nRTS is enabled again. \nYou should see the keys you hit just now.\n");
		break;
	case 's':
		ioctl(f, TIOCMGET, &rtscts);
		if(rtscts&TIOCM_RTS)
			printf("RTS on %s is enabled.\n", devname);
		else
			printf("RTS on %s is disabled.\n", devname);
		if(rtscts&TIOCM_CTS)
			printf("CTS on %s is enabled.\n", devname);
		else
			printf("CTS on %s is disabled.\n", devname);
		break;
	}

	close(f);

	return 0;
}
