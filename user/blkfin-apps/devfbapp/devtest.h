#define M_ERROR 20 	// It doesnt matter what value we asign as long as it is greater than 1. This is done to avoid "divide by 0" situation.
char *device = "/dev/fb0";

struct fb_var_screeninfo screeninfo;
int screen_fd;
unsigned char * screen_ptr;
int screen_width;
int screen_height;
int bits_per_pixel;
int left_mar;
int right_mar;
int up_mar;
int low_mar;


void dev_init_func(){
	screen_fd = open(device, O_RDWR);
	if (ioctl(screen_fd, FBIOGET_VSCREENINFO, &screeninfo)==-1) {
                perror("Unable to retrieve framebuffer information");
                exit(0);
        }
        screen_width    = screeninfo.xres_virtual;
        screen_height 	= screeninfo.yres_virtual;
        bits_per_pixel	= screeninfo.bits_per_pixel;
	left_mar 	= screeninfo.left_margin;
	right_mar 	= screeninfo.right_margin;
	up_mar 		= screeninfo.upper_margin;
	low_mar 	= screeninfo.lower_margin;
        screen_ptr = mmap(0, screen_height * screen_width * (bits_per_pixel/ 8), PROT_READ|PROT_WRITE, 0, screen_fd, 0);
  
        if (screen_ptr==MAP_FAILED) {
                perror("Unable to mmap frame buffer\n"); 
        }
}
void draw_pixel(int x, int y, int color)
{
        int mask = 1 << (7-(x % 8));
        //unsigned int * loc = screen_ptr + ((y - 1) * screen_width *(bits_per_pixel/8)) + (x * (bits_per_pixel/8));
        unsigned int * loc = screen_ptr + ((y - 1) * 360 *(bits_per_pixel/8)) + (x * (bits_per_pixel/8));
        if ((x<0) || (x>=screen_width) || (y<0) || (y>=screen_height))
                return;
        *loc = color;
}
void draw_line(float x1,float y1,float x2,float y2,int color)
{
	float m,c,x=x1,y=y1,dy,dx;
	x = x1;
	y = y1;
	if (x1 != x2) {
		m = (y2 -y1) / (x2-x1); 
		c = y1 -(m * x1);
	}
	else
		m = M_ERROR;
	if((m *m)>=1)
		for(;;)
		{
			if(x1 != x2) 
			x=(y-c)/m;
			draw_pixel(x,y,color);
			if(y2>y1)
				y++;
			else
				y--;		
			dy=y-y2;
			if(dy == 0)
				break;
				else
				continue;
		}
	else
		for(x=x1;;){
			y = (m * x) + c;
			draw_pixel(x,y,color);
			if(x2>x1)
				x++;
				else
				x--;		
			dx = x -x2;
			if(dx == 0)
				break;
			else
				continue;
		}
}
void fillscreen(int color)
{
	int i;
	int *screen_base_add;
	(char *)screen_base_add = screen_ptr;
	for(i=0; i<188640; i++)
        	*(screen_base_add+ i) = color;
}
void time_delay_func(int delay){
	int current_time_sec;			//time in second
	current_time_sec = clock() / HZ;
	for(;;)
		if(current_time_sec -(clock()/ HZ) == delay)                  // Condition is equivalent to 2 secs.
			break;
}
