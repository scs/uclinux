#include <stdlib.h>
#include <string.h>
#include <nwidgets.h>

static int button_init (NBUTTON * this, NWIDGET * parent, const char * text)
{
   if (n_widget_init(this,parent)) return -1;
   this->pressed = 0;
   this->text = (char *)strdup(text); 
   this->onclick_handler = 0;
   
   return 0;
}

static void button_cleanup (NBUTTON * this)
{
   if (this->text) free(this->text);
   n_super(object,cleanup,this,(this));
}

static void button_repaint (NBUTTON * this)
{
   int w,h;
   int tw,th,tb,x,y;
   int len;
   
   MWCOLORVAL textcol;
   NRENDER * rob;
   
   textcol = n_widget_getrendercol(this,RCOL_WIDGET_TEXT);
   rob = n_widget_getrenderob(this);
   
   n_widget_getgeometry(this,0,0,&w,&h);
   n_render_panel(rob,this,0,0,w,h,this->pressed);
   n_widget_setfg(this,textcol);
   
   if (!this->text) return;
   
   len = strlen(this->text);

   tw = th = tb = 0;
   n_widget_textextent(this,this->text,len,&tw,&th,&tb);

   x = (w-tw)/2;
   y = (h+th-tb)/2;
   if (x<0) x=0;
   if (y<0) y=0;
   
   n_widget_text(this,x,y,this->text,len);
}

static void button_buttondown(NBUTTON * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) this->pressed = 1;
   n_widget_repaint(this);
}

static void button_buttonup(NBUTTON * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) this->pressed = 0;
   n_widget_repaint(this);
}

static void button_clicked(NBUTTON * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) {
      if (this->pressed && this->onclick_handler) this->onclick_handler(this,b);
      this->pressed = 0;
   }
   n_widget_repaint(this);
}

static void button_onclick(NBUTTON * this, void (* h)(NBUTTON *, unsigned int))
{
   this->onclick_handler = h;
}

/* Implement the n_init_widget_class() function */
INIT_NCLASS(button,widget)

  /* Initialize the proper method slots with new and overridden methods */
  NMETHOD(button,init,button_init);
  NMETHOD(object,cleanup,button_cleanup);
  NMETHOD(widget,repaint,button_repaint);
  NMETHOD(widget,buttondown,button_buttondown);
  NMETHOD(widget,buttonup,button_buttonup);
  NMETHOD(widget,clicked,button_clicked);
  NMETHOD(button,onclick,button_onclick);
END_INIT
