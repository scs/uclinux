#include <nwidgets.h>

static int render_init (NRENDER * this)
{
   if (n_object_init(this)) return -1;
   
   /* Initialize default colors */
   
   this->colors[RCOL_WIDGET_BACKGROUND] = GRAY;
   this->colors[RCOL_WIDGET_TEXT] = BLACK;
   this->colors[RCOL_WIDGET_TEXTBACKGROUND] = LTGRAY;
   this->colors[RCOL_WIDGET_DARK] = BLACK;
   this->colors[RCOL_WIDGET_MEDIUM] = GRAY;
   this->colors[RCOL_WIDGET_LIGHT] = WHITE;
   this->colors[RCOL_HIGHLIGHTED] = LTBLUE;
   this->colors[RCOL_CURSOR] = BLUE;
   
   return 0;
}

static void render_cleanup (NRENDER * this)
{
   n_super(object,cleanup,this,(this));
}

static MWCOLORVAL render_getcolor (NRENDER * this, int col)
{
   if (col>RCOL_MAXCOL || col < 0) return -1;
   return this->colors[col];
}

static void render_border(NRENDER * this, NWIDGET * widget, int x,int y, int w,int h, int pressed)
{
   n_widget_setfg(widget,this->colors[pressed ? RCOL_WIDGET_DARK : RCOL_WIDGET_LIGHT]);
   n_widget_line(widget,x,y,x+w-1,y);
   n_widget_line(widget,x,y,x,y+h-1);
   n_widget_setfg(widget,this->colors[!pressed ? RCOL_WIDGET_DARK : RCOL_WIDGET_LIGHT]);
   n_widget_line(widget,x+w-1,y+1,x+w-1,y+h-1);
   n_widget_line(widget,x+1,y+h-1,x+w-1,y+h-1);

}

static void render_panel(NRENDER * this, NWIDGET * widget, int x,int y, int w,int h, int pressed)
{
   n_widget_setfg(widget,this->colors[!pressed ? RCOL_WIDGET_BACKGROUND : RCOL_HIGHLIGHTED]);
   n_widget_fillrect(widget,x,y,w,h);
   n_render_border(this,widget,x,y,w,h,pressed);
}

INIT_NCLASS(render,object)

  /* Initialize the proper method slots with new and overridden methods */
  NMETHOD(render,init,render_init);
  NMETHOD(object,cleanup,render_cleanup);
  NMETHOD(render,getcolor,render_getcolor);
  NMETHOD(render,border,render_border);
  NMETHOD(render,panel,render_panel);
END_INIT
