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
	0x10801080,
	0x51F0515A,
	0x91229136,
	0xAA10AAA6,
	0xEB80EB80
		} ;

int screen_fd ;
char *device = "/dev/vout0";
#define MAX_BUFFERS 23 /* the ultimate upper limit */
struct v4l2_standard user_vid_std ;
struct v4l2_format user_fmt;
char *user_buffer[MAX_BUFFERS];
int linenum =0;
int byteheight ;
int bytewidth ;
int bytesizeimage ;
void draw_color_bars(int *);

void
usage(char *program)
{
  fprintf(stderr, "usage : %s [options]\nwhere options can be :"
	"\n\t[-d : wait 1 sec before write]"
	"\n\t[-b <buf_count : max/default %d>]"
	"\n\t[-l <loop_count : min 1, default : 100>]"
	"\n\t[-v : verbose]"
	"\n", 
	program, MAX_BUFFERS);
  exit(0);
}

int main(int argc, char *argv[])
{
	int i, j, k; 
	float current_time1, current_time2;
	int nMaxBuffers = MAX_BUFFERS;
	int bDelay = 0;
	int nLoopCount = 100;
	int bVerbose = 0;
	int nbuffers; 

	if(argc > 1){
		for(i = 1; i < argc; i++){
			if(!strcmp(argv[i], "-d")){
				bDelay = 1;
			}
			else if(!strcmp(argv[i], "-v")){
				bVerbose = 1;
			}
			else if(!strcmp(argv[i], "-b")){
				nbuffers = atoi(argv[i+1]);
				if(nbuffers > 0 && nbuffers <= MAX_BUFFERS){
					nMaxBuffers = nbuffers;
					i++;
				}
				else{
					usage(argv[0]);
				}
			}
			else if(!strcmp(argv[i], "-l")){
				nLoopCount = atoi(argv[i+1]);
				i++;
				if(nLoopCount < 1){
					usage(argv[0]);
				}
			}
			else{
				usage(argv[0]);
			}
		}
	}
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

	fprintf(stderr, "setting up buffers, Please wait\n");
	for(i=0; i<nMaxBuffers; i++) {
		user_buffer[i] = malloc((bytewidth * byteheight) +10);
		if(user_buffer[i] == NULL) {
			if(bVerbose)
				fprintf(stderr, "memory allocation for buffer %d failed, using limited buffers\n", i);
			break ;
		}
		draw_color_bars(user_buffer[i]) ;
		if(i%4 == 0)
			linenum -=1;
		fprintf(stderr, ".");
	}
	k = i;
	nMaxBuffers = i ;
	if(bVerbose && (k < 8)){
		fprintf(stderr, "\nTo get the best in the demo, increase memory\n");
	}
	fprintf(stderr,"Done.\nBuffers are set, starting demo. Watch the output on your TV!\n");
	current_time1 = clock()/CLOCKS_PER_SEC;
	for(j=0; j< nLoopCount; j++)
		for(i = 0; i<k; i++) {
			write(screen_fd, user_buffer[i], bytesizeimage);
			if(bVerbose)
				fprintf(stderr, "Buffer %d written \n", i);
			if(bDelay)
				sleep(1);
		}
		
	fprintf(stderr, "\t****End Of Demo****\n");
	current_time2 = clock()/CLOCKS_PER_SEC;
	fprintf(stderr, "number of frames per second = %f \n", ((nLoopCount*k)/(current_time2 - current_time1)));
	sleep(2);
	//release buffers.
	for(i = 0; i<23 ; i++) 
		if(user_buffer[i]) 
			free(user_buffer[i]) ;
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
