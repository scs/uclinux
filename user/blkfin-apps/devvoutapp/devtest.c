#include <sys/types.h>
#include <stdlib.h>
#include <linux/fb.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <time.h>

int colorarray[] = {
	   0x80108010,
	   0x5A51F051,
	   0x36912291,
	   0xA6AA10AA,
	   0x80EB80EB
		} ;

int screen_fd ;
char *device = "/dev/vout0";
FILE *userfile ;
struct v4l2_standard user_vid_std ;
struct v4l2_format user_fmt;
char *user_buffer[50];
int linenum =0;
int byteheight ;
int bytewidth ;
int bytesizeimage ;
void draw_color_bars(int *);

int main(int argc, char *argb[])
{
	int i, j, current_time1, current_time2;
	screen_fd = open(device, O_RDWR);
	if (screen_fd == -1) {
		perror("Unable to open vout device /dev/vout0\n");
		exit(0);
	}
	user_vid_std.index = 0;
	ioctl(screen_fd, VIDIOC_ENUMSTD, &user_vid_std);
	if(user_vid_std.id != V4L2_STD_NTSC) {
		fprintf(stderr, "Error: NTSC not supported\n");
		exit(0);
	}
	
	user_fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	ioctl(screen_fd, VIDIOC_G_FMT, &user_fmt);
	byteheight = user_fmt.fmt.pix.height *4 ;
	bytewidth  = user_fmt.fmt.pix.width *4 ;
	bytesizeimage = user_fmt.fmt.pix.sizeimage *4;

	for(i=0; i<50; i++) {
		user_buffer[i] = malloc((bytewidth * byteheight) +10);
		draw_color_bars(user_buffer[i]) ;
		if(i%4 == 0)
			linenum -=1;
	}
	current_time1 = clock()/CLOCKS_PER_SEC;
	for(j=0; j< 20; j++)
		for(i = 0; i<50; i++)
			write(screen_fd, user_buffer[i], bytesizeimage);
	current_time2 = clock()/CLOCKS_PER_SEC;
	fprintf(stderr, "number of frames per second = %d \n", (1000/(current_time2 - current_time1)));
	
	sleep(3);
	return 0;

}
void draw_color_bars(int * ycrcb)
{
	int i, j, k;
	linenum += 10 ;
	for(k=0; k<5; k++) {
		for(j=1; j<=105;j++){
			for(i=0; i<360; i++){
				ycrcb[linenum*360 +i] = colorarray[k] ;
			}
			if(linenum++ >= 524)
				linenum -= 524;
		}
	}
}
