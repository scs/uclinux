#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h> 
#include <string.h>

#include <linux/input.h>

int main(int argc, char *argv[])
{
	int ret;
	char f_name[30];
	int nr = 0;
	struct pollfd p_fd[1];
	int p_res;
	struct input_event ie;
	
	if(argc>2) {
		printf("usage: pfbuttons_test [nr]\n where nr is the event device (from 0 to 31)");
		return 0;
	}
	if (argc>1){
		nr = atoi(argv[1]);
	}
	if (nr<0 && nr>31){
		printf("usage: pfbuttons_test [nr]\n where nr is the event device (from 0 to 31)");
	}
	sprintf(f_name,"/dev/input/event%d",nr);
	printf("########################## PFBUTTONS TEST ###############################\n");
		
	p_fd[0].fd = open(f_name, O_RDWR|O_NONBLOCK,0);
	if (p_fd[0].fd == -1) {
		printf("%s open error %d\n", f_name, errno);
		exit(1);
	}
	else printf("open success %s \n", f_name);

	while(1) {
		p_fd[0].revents = 0;
		p_fd[0].events = POLLIN | POLLERR;
		p_res = poll(p_fd,1,10);
		if (p_res<0){
			perror("read!");
			exit(1);
		}
		if (p_res>0){
			if (p_fd[0].revents & POLLIN){
				while(read(p_fd[0].fd,&ie,sizeof(ie))>0){
					printf("Event. Type: %d, Code: %d, Value: %d\n",ie.type, ie.code, ie.value);
					if (ie.type == EV_KEY){
						switch(ie.code){
							case BTN_0:
								printf("Take a look LED_MUTE ... %s\n",((ie.value)?"on":"off"));
								ie.type = EV_LED;
			    				ie.code = LED_MUTE;
			    				break;
							case BTN_1:
								printf("Hear SND_BELL ... %s\n",((ie.value)?"on":"off"));
								ie.type = EV_SND;
			    				ie.code = SND_BELL;
			    				break;
		    				case BTN_2:
								printf("Take a look LED_MISC ... %s\n",((ie.value)?"on":"off"));
								ie.type = EV_LED;
			    				ie.code = LED_MISC;
			    				break;
							case BTN_3:
								printf("Take a look LED_SUSPEND ... %s\n",((ie.value)?"on":"off"));
								ie.type = EV_LED;
			    				ie.code = LED_SUSPEND;
			    				break;
						}
			    		if (ie.type != EV_KEY){
							if (write(p_fd[0].fd, &ie, sizeof(ie))<0){
								printf("Not handlet event!\n");
							}
			    		}
					}
				}
			}else if (p_fd[0].revents & POLLERR){
				break;	
			}
		}
	}
	printf("Exit\n");
	close(p_fd[0].fd);
	exit(0);
}
