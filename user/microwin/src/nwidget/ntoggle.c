#include <nwidgets.h>

static int toggle_init (NTOGGLE * this, NWIDGET * parent)
{
   if (n_widget_init(this,parent)) return -1;
   this->pressed = 0;
   this->selected = 0;
   this->onchange_handler = 0;
   
   return 0;
}

static void toggle_cleanup (NTOGGLE * this)
{
   n_super(object,cleanup,this,(this));
}

static void toggle_paintstate (NTOGGLE * this, int state)
{
   int w,h;
   n_widget_getgeometry(this,0,0,&w,&h);
   if (state) {
      n_widget_setfg(this,0);
      n_widget_line(this,3,(h/2),((w-4)/2),h-3);
      n_widget_line(this,2,(h/2),((w-4)/2),h-2);
      n_widget_line(this,((w-5)/2),h-2,w-5,2);
      n_widget_line(this,((w-4)/2),h-2,w-4,2);
   }
}

static void toggle_repaint (NTOGGLE * this)
{
   int w,h;
   NRENDER * rob;
   n_widget_getgeometry(this,0,0,&w,&h);
   rob = n_widget_getrenderob(this);   
   n_render_panel(rob,this,0,0,w,h,this->pressed);
   n_toggle_paintstate(this,this->selected);
}

static int toggle_isselected (NTOGGLE * this)
{
   return this->selected;
}

static void toggle_setstate(NTOGGLE * this, int state)
{
   if (this->selected != state) {
      this->selected = state;
      if (this->onchange_handler) this->onchange_handler(this,state);
      n_widget_repaint(this);
   }
}

static void toggle_buttondown(NTOGGLE * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) {
      this->pressed = 1;
      n_toggle_setstate(this,this->selected ? 0 : 1);
   }
}

static void toggle_buttonup(NTOGGLE * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) {
      this->pressed = 0;
      n_widget_repaint(this);
   }
}

static void toggle_onchange(NTOGGLE * this, void (* h)(NTOGGLE *,int))
{
   this->onchange_handler = h;
}

/* Implement the n_init_widget_class() function */
INIT_NCLASS(toggle,widget)

  /* Initialize the proper method slots with new and overridden methods */
  NMETHOD(toggle,init,toggle_init);
  NMETHOD(toggle,onchange,toggle_onchange);
  NMETHOD(toggle,setstate,toggle_setstate);
  NMETHOD(toggle,paintstate,toggle_paintstate);
  NMETHOD(toggle,isselected,toggle_isselected);

  NMETHOD(widget,repaint,toggle_repaint);
  NMETHOD(widget,buttondown,toggle_buttondown);
  NMETHOD(widget,buttonup,toggle_buttonup);
  NMETHOD(widget,clicked,toggle_buttonup);

  NMETHOD(object,cleanup,toggle_cleanup);

END_INIT
