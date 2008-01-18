#include <sys/types.h>
#include <stdlib.h>
#include <linux/fb.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <asm/param.h>
#include "devtest.h"

#define YELLOW  0x00ff00ff 
#define RED     0x000000ff 
#define BLUE    0xff00ff00 
#define GREEN   0x00ff0000 
#define WHITE   0xffffffff
#define BLACK	0x00
#define OFFSET  37800

int main(int argc, char *argb[])
{
	dev_init_func();
	int i;
	for(;;){
		for(i=0;i<756000;i++)
			*(screen_ptr+i) = 0xff;
		for(i = 0;i<100;i++)
			draw_line(130+i, 212, 130+i, 312, BLUE);
		sleep(1);
		for(i = 0;i<100;i++)
			draw_line(130+i, 212, 130+i, 312, WHITE);

		for(i = 0;i<100;i++)
			draw_line(left_mar +i, 0, left_mar + i, up_mar +100, RED);
		sleep(1);
		for(i = 0;i<100;i++)
			draw_line(left_mar +i, up_mar, left_mar +i, up_mar +100, WHITE);

		for(i = 0;i<100;i++)
			draw_line(left_mar +i, screen_height - low_mar -100, left_mar +i, screen_height - low_mar, GREEN);
		sleep(1);        
		for(i = 0;i<100;i++)
			draw_line(left_mar +i, screen_height - low_mar -100, left_mar +i, screen_height - low_mar, WHITE);
	
		for(i = 0;i<100;i++)
			draw_line(screen_width - right_mar -100 +i, 0, screen_width -right_mar -100 +i, up_mar +100, YELLOW);
		sleep(1);
		for(i = 0;i<100;i++)
			draw_line(screen_width - right_mar -100 +i, up_mar, screen_width -right_mar -100 +i, up_mar +100, WHITE);

		for(i = 0;i<100;i++)
			draw_line(screen_width -right_mar  -100 +i, screen_height -low_mar -100, screen_width -right_mar  -100 +i, screen_height -low_mar, BLACK);
		sleep(1);
		for(i = 0;i<100;i++)
			draw_line(screen_width -right_mar  -100 +i, screen_height -low_mar -100, screen_width -right_mar  -100 +i, screen_height -low_mar, WHITE);
	}	
	for(;;);
}
