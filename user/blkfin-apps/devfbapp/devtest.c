#include <sys/types.h>
#include <linux/fb.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <asm/param.h>
#include "devtest.h"


int main(int argc, char *argb[])
{
	int black =0, yellow = 0x00ff00ff, red = 0x000000ff, blue = 0xff00ff00, green = 0x00ff0000, white = 0xffffffff, offset = 37800;
	dev_init_func();
	int i;
	for(i=0;i<756000;i++)
        *(screen_ptr+i) = 0xff;
	for(i = 0;i<100;i++)
		draw_line(130+i, 212, 130+i, 312, blue);
	sleep(2);
	for(i = 0;i<100;i++)
		draw_line(left_mar +i, up_mar, left_mar +i, up_mar +100, red);
	sleep(2);
	for(i = 0;i<100;i++)
		draw_line(left_mar +i, screen_height - low_mar -100, left_mar +i, screen_height - low_mar, green);
	sleep(2);
	for(i = 0;i<100;i++)
		draw_line(screen_width - right_mar -100 +i, up_mar, screen_width -right_mar -100 +i, up_mar +100, yellow);
	sleep(2);
	for(i = 0;i<100;i++)
		draw_line(screen_width -right_mar  -100 +i, screen_height -low_mar -100, screen_width -right_mar  -100 +i, screen_height -low_mar, black);
		
	for(;;);
}
