/* Capture from a video4linux camera driver 
 * */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <linux/videodev.h>


#define DEVICE_FILE "/dev/video0"
#define HEIGHT 288
#define WIDTH 352
#define DEFAULT_FMT VIDEO_PALETTE_YUV422
#define DEFAULT_LEN 16
#define DEFAULT_RATE 30

static int try_format(int fd, struct video_picture *pict, int palette, int depth);
static int try_size(int fd, int width, int height);
static int do_mmap(int fd, struct video_mbuf * pvmbuf, char ** pbuf);

int frame_rate = DEFAULT_RATE;
char * outfile = NULL;
char pix_buf[(HEIGHT * WIDTH * 2)];

int parse_cmd(int argc, char ** argv)
{
	int arg_num = 1;
	if (argc < 2) {
		printf("usage: video_cap [-r <frame_rate>] [-o <output file>]");
		printf("using default setting\n");
		return 0;
	}

	while (arg_num < argc) {
		int old_arg_num = arg_num;
		if (strncmp ("-r", argv[arg_num], 2) ==0) {
			arg_num++;
			if (arg_num < argc) {
				frame_rate = atoi (argv[arg_num]);
			}
			else
				frame_rate = DEFAULT_RATE;
		} else if (strncmp ("-o", argv[arg_num], 2) == 0) {
			arg_num++;
			if (arg_num < argc)
				outfile = argv[arg_num];
		} else if (old_arg_num == arg_num) {
			printf("usage: video_cap [-r <frame_rate>] [-o <output file>]");
		}
		arg_num++;
	}
	return 0;
}

long get_cur_ms()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

int main (int argc, char **argv)
{
	int err = -1;
	int done = 0;
	int j = 0;
	int devfd = 0, outfd = 0;
	char * vbuf = NULL, *ptr = NULL;
	int frame_size = 0;
	
	struct video_capability vidcap;
	struct video_mbuf vmbuf;
	struct video_mmap vmmap;
	struct video_picture pict;
	int frame_id = 0;
	int frame_cnt = 0;
	long start_ms = 0, now_ms = 0, offset_ms = 0;
	
	parse_cmd(argc, argv);

	printf("capture rate: %d, height: %d, widht: %d\n", frame_rate, HEIGHT, WIDTH);
	if (outfile) {
		printf("device: %s, output: %s\n", DEVICE_FILE, outfile);
		outfd = open(outfile, O_RDWR|O_CREAT|O_TRUNC);
		if (outfd < 0) {
			printf("cannot open %s\n", outfile);
			return -1;
		}
	}

	printf("open %s\n", DEVICE_FILE);
	devfd = open(DEVICE_FILE, O_RDWR);
	if (devfd < 0) {
		printf("cannot open %s\n", DEVICE_FILE);
		return -1;
	}

	err=ioctl(devfd, VIDIOCGCAP, &vidcap);
	if (err!=0) {
		printf("cannot get device capabilities: %s.\n",strerror(errno));
		return -1;
	}

	fprintf(stdout, "found %s device. (maxsize=%ix%i)\n",vidcap.name, vidcap.maxwidth, vidcap.maxheight);

	/* get picture properties */
	err=ioctl(devfd, VIDIOCGPICT, &pict);
	if (err<0){
		printf("could not get picture properties: %s\n",strerror(errno));
		return -1;
	}
	fprintf(stdout, "default picture properties: brightness=%i,hue=%i,colour=%i,contrast=%i,depth=%i, palette=%i.\n",
		pict.brightness,pict.hue,pict.colour, pict.contrast,pict.depth, pict.palette);

	/* check whether this format is supported */
	if (!try_format(devfd, &pict, DEFAULT_FMT, DEFAULT_LEN)) {
		printf("unsupported video pixel format.\n");
		return -1;
	}

	if (!try_size(devfd, WIDTH, HEIGHT))
		return -1;

	if (do_mmap(devfd, &vmbuf, &vbuf)) {
		printf("cannot mmap\n");
	}
	
	frame_size = vmbuf.size;
	frame_id = 0;

	/* start to grab */
	vmmap.height = HEIGHT;
	vmmap.width = WIDTH;
	vmmap.format = pict.palette;
	
	for (j = 0; j < vmbuf.frames; j++) {
		vmmap.frame = j;
		ioctl(devfd, VIDIOCMCAPTURE, &vmmap);
	}

	/* capture */
	start_ms = get_cur_ms();
	do {
		while (ioctl(devfd, VIDIOCSYNC, &frame_id) < 0 &&
           		(errno == EAGAIN || errno == EINTR));
		ptr = vbuf + vmbuf.offsets[frame_id];

		if (outfile) {
			memcpy(pix_buf, ptr, frame_size);
			err = write(outfd, pix_buf, frame_size);
			//err = write(outfd, ptr, frame_size);
			if (err < frame_size) {
				printf("write error:%s\n", strerror(errno));
				return -1;
			}
		}

		/* setup to capture the next frame */
		vmmap.frame = frame_id;
		if (ioctl(devfd, VIDIOCMCAPTURE, &vmmap) < 0) {
			perror("VIDIOCMCAPTURE");
        		return -1;
		}
		
		/* this is now the grabbing frame */
		frame_id = (frame_id + 1) % vmbuf.frames;
		
		/* capture rate control */
		frame_cnt++;
		now_ms = get_cur_ms() - start_ms;
		offset_ms = frame_cnt * 1000 / frame_rate;
		if (offset_ms > now_ms)
			usleep((offset_ms - now_ms) * 1000);
	} while (!done);

	return 0;
}

static int try_format(int fd, struct video_picture *pict, int palette, int depth){
	int err;
	pict->palette=palette;
	pict->depth=depth;
	err=ioctl(fd,VIDIOCSPICT,pict);
	if (err<0){
		printf("could not set picture properties: %s\n",strerror(errno));
		return 0;
	}
	return 1;
}

static int try_size(int fd, int width, int height){
	struct video_window win;
	int err;
	memset(&win,0,sizeof(win));
	/*set picture size */
	win.x=win.y=0;
	win.width=width;
	win.height=height;
	win.flags=0;
	win.clips=NULL;
	win.clipcount=0;

	printf("trying to set capture size to %ix%i\n", width,height);
	err=ioctl(fd,VIDIOCSWIN,&win);
	if (err<0){
		printf("could not set window size: %s\n",strerror(errno));
		return 0;
	}

	err=ioctl(fd, VIDIOCGWIN, &win);
	if (err<0){
		printf("could not get window size: %s\n",strerror(errno));
		return 0;
	}
	if (width!=win.width || height!=win.height){
		printf("capture size is not what we expected: asked for %ix%i and get %ix%i\n",
			width, height, win.width, win.height);
		return 0;
	}

	printf("capture size set to %ix%i\n", width,height);
	return 1;
}

static int do_mmap(int fd, struct video_mbuf * pvmbuf, char ** pbuf){
	int err;

	memset((void*)pvmbuf,0,sizeof(*pvmbuf));
	/* try to get mmap properties */
	err=ioctl(fd,VIDIOCGMBUF,pvmbuf);
	if (err<0){
		printf("could not get mmap properties: %s\n",strerror(errno));
		return -1;
	}

	*pbuf =mmap(NULL,pvmbuf->size,PROT_READ,MAP_PRIVATE,fd,0);
	if (*pbuf == (void*)-1) {
		printf("could not mmap: %s\n",strerror(errno));
		return -1;
	}
	
	return 0;
}
