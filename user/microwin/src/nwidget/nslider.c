#include <nwidgets.h>

/* Strictly internal. We dont export the interface for this one */
static void slider_calcbounds(NSLIDER * this, int * x, int * y, int * w, int * h)
{
   *x = 2 + ((*w * this->rel_x) / this->rel_maxw);
   *y = 2 + ((*h * this->rel_y) / this->rel_maxh);

   *w = (*w / (this->rel_maxw / this->rel_w)) - 4;
   *h = (*h / (this->rel_maxh / this->rel_h)) - 4;       
}

/* Make sure noone are playing tricks with the slider boundaries... */
static void slider_enforcebounds(NSLIDER * this) 
{
   if (this->rel_x < 0) this->rel_x = 0;
   if (this->rel_y < 0) this->rel_y = 0;
   if (this->rel_x > (this->rel_maxw - this->rel_w)) this->rel_x = this->rel_maxw - this->rel_w;
   if (this->rel_y > (this->rel_maxh - this->rel_h)) this->rel_y = this->rel_maxh - this->rel_h;
}

static void slider_buttondown(NSLIDER * this, int x, int y, unsigned int b)
{
   int bx,by,bw,bh;
   if (b & GR_BUTTON_L) {
      n_widget_getgeometry(this,0,0,&bw,&bh);
      slider_calcbounds(this,&bx,&by,&bw,&bh);
      
      if (x>=bx && x<= (bx+bw) &&
	  y>=by && y<= (by+bh)) {
      
	 this->pressed = 1;
	 this->ox = x;
	 this->oy = y;
      }
   }
   n_widget_repaint(this);
}

static void slider_buttonup(NSLIDER * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) {
      this->pressed = 0;
      this->ox = 0;
      this->oy = 0;
   }
   n_widget_repaint(this);
}

static void slider_mousemove(NSLIDER * this, int x, int y, unsigned int b)
{
   int w,h;
   
   if (this->pressed) {
      n_widget_getgeometry(this,0,0,&w,&h);
      //printf("MOUSEMOVE: x=%d,y=%d\n",x,y);

      /* FIXME: Change rel_x/rel_y, based on ox-x and oy-y reset offset */
      if (this->freedom & NSLIDER_FREEDOM_HORIZONTAL) {
	 this->rel_x += ((x - this->ox) * (this->rel_maxw / (w-4)));
      }
      if (this->freedom & NSLIDER_FREEDOM_VERTICAL) {
	 this->rel_y += ((y - this->oy) * (this->rel_maxh / (h-4)));
      }
      //printf("this->rel_y = %d, this->oy = %d, y=%d, this->rel_maxh / h = %d\n",this->rel_y, this->oy,y,this->rel_maxh / h);
      this->ox = x;
      this->oy = y;
   
      slider_enforcebounds(this);
      
      n_widget_repaint(this);
   }
}

static void slider_repaint (NSLIDER * this)
{
   int w,h,x,y;
   
   NRENDER * rob;
   
   rob = n_widget_getrenderob(this);
   n_widget_getgeometry(this,0,0,&w,&h);
   
   n_widget_setfg(this,LTGRAY);
   n_widget_setbg(this,LTGRAY);
   n_widget_fillrect(this,1,1,w-2,h-2);
   n_render_border(rob,this,0,0,w,h,1);
   
   slider_calcbounds(this,&x,&y,&w,&h);
#ifdef DEBUG   
   fprintf(stderr,"SLIDER: x=%d, y=%d, w=%d, h=%d\n",x,y,w,h);
#endif
   n_render_panel(rob,this,x,y,w,h,this->pressed);
   
}

static int slider_init (NSLIDER * this, NWIDGET * parent)
{
   if (n_widget_init(this,parent)) return -1;
   
   this->pressed = 0;
   this->freedom = NSLIDER_FREEDOM_VERTICAL | NSLIDER_FREEDOM_HORIZONTAL; 
   
   this->rel_maxw = 1000;
   this->rel_maxh = 1000;
   this->rel_w = 100;
   this->rel_h = 100;
   this->rel_x = 0;
   this->rel_y = 50;

   this->move_handler = 0;
   
   return 0;
}

INIT_NCLASS(slider,widget)
    NMETHOD(slider,init,slider_init); 
    NMETHOD(widget,repaint,slider_repaint); 
    NMETHOD(widget,buttondown,slider_buttondown);
    NMETHOD(widget,buttonup,slider_buttonup);
    NMETHOD(widget,clicked,slider_buttonup); /* No difference between click and buttonup for slider...*/
    NMETHOD(widget,mousemove,slider_mousemove);
END_INIT
