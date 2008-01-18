
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

//****************Routine to open frame buffer device and initialise associated perpherals accordingly**************
//****************actual implementation in driver, here we are calling those driver func only.***************

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


//***************Routine to draw a particular pixel with given color*********************

void draw_pixel(int x, int y, int color)
{
        unsigned int * loc = (unsigned int *)(screen_ptr + ((y - 1) * 360 *(bits_per_pixel/8)) + (x * (bits_per_pixel/8)));
        if ((x<0) || (x>=screen_width) || (y<0) || (y>=screen_height))
                return;
        *loc = color;
}

//*****************Routine to draw line between two given coordinates with given color***********************

void draw_line(float x1,float y1,float x2,float y2,int color)
{
	float m = 0,c = 0,x=x1,y=y1,dy,dx;
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


//*******************Routine to draw filled quadrilateral*********************

void draw_filled_quadrilateral(float x1, float y1, float x2, float y2, float x3, float y3, float x4, float y4, int color)
{
	float X1=x1, Y1=y1, X2=x2, Y2=y2, X3=x3, Y3=y3, X4=x4, Y4=y4, AB, AC, AD;
	float m1 = 0, m2 = 0, c1 = 0, c2 = 0, dX1 = 5.0, dX4 = 5.0, dY1 = 5.0, dY4 = 5.0;
	int i;


	AB = (x1 -x2) * (x1 -x2) + (y1 - y2) * (y1 - y2);
        AC = (x1 -x3) * (x1 -x3) + (y1 - y3) * (y1 - y3);
        AD = (x1 -x4) * (x1 -x4) + (y1 - y4) * (y1 - y4);

	if(AB > AC || AB > AD) {
		X2 =x3;
		Y2 =y3;
		X3 =x2;
		Y3 =y2;
	}
	if(AD >	AC || AD > AB) {
		X3 = x4;
		Y3 = y4;
		X4 = x3;
		Y4 = y3;
	}



	if (X1 != X2) {
		m1 = (Y2 -Y1) / (X2-X1); 
		c1 = Y1 -(m1 * X1);
	}
	else
		m1 = M_ERROR;
	if (X3 != X4) {
		m2 = (Y3 -Y4) / (X3-X4); 
		c2 = Y3 -(m2 * X3);
	}
	else
		m2 = M_ERROR;

	for(i = 0;(dX1 >=1 || dX4 >=1 || dY1 >=1 || dY4 >=1) && (i <636);i++){
		draw_line(X1, Y1, X4, Y4, color);
		if((m1 *m1)>=1)
		{
			if(dY1 >=1){
				if(X1 != X2) 
					X1=(Y1-c1)/m1;
				if(Y2>Y1)
					Y1++;
				else
					Y1--;		
				dY1=Y1-Y2;
			}
		}
		else 
		{
			if(dX1 >=1){
				Y1 = (m1 * X1) + c1;
				if(X2>X1)
					X1++;
				else
					X1--;		
				dX1 = X1 -X2;
			}
		}

		if((m2 *m2)>=1)
		{
			if(dY4 >=1){
				if(X4 != X3) 
				X4=(Y4-c2)/m2;
				if(Y4>Y3)
					Y4++;
				else
					Y4--;		
				dY4=Y3-Y4;
			}
		}
		else
		{
			if(dX4 >=1){
				Y4 = (m2 * X4) + c2;
				if(X3>X4)
					X4++;
				else
					X4--;		
				dX4 = X4 -X3;
			}
		}
	}
}
