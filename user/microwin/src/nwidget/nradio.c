#include <nwidgets.h>

static int radio_init (NRADIO * this, NWIDGET * parent)
{
   if (n_toggle_init(this,parent)) return -1;
   
   this->next_radio = this;
   this->last_radio = this;
   
   return 0;
}

static void radio_cleanup (NTOGGLE * this)
{
   n_super(object,cleanup,this,(this));
}

static void radio_paintstate (NRADIO *this, int state)
{
   int w,h;
   n_widget_getgeometry(this,0,0,&w,&h);
   if (state) {
      n_widget_setfg(this,0);
      n_widget_line(this,2,2,w-2,h-2);
      n_widget_line(this,3,2,w-2,h-3);
      n_widget_line(this,w-2,2,2,h-2);
      n_widget_line(this,w-3,2,2,h-3);
   }
}

static void radio_connect(NRADIO * this, NRADIO * ob)
{
   ob->next_radio = this->next_radio;
   ob->last_radio = this;
   
   this->next_radio = ob;
   ob->next_radio->last_radio = ob;

   n_toggle_setstate(this,1);
}

static void radio_setstate(NRADIO * this, int state)
{
   NRADIO * tmp;
   
   n_super(toggle,setstate,this,(this,state));
   
   /* Reverse state for all the others in this group */
   state = state ? 0 : 1;
   tmp = this->next_radio;
   while (tmp != this) {
      n_super(toggle,setstate,tmp,(tmp,state));
      tmp = tmp->next_radio;
   }
}

static void radio_buttondown(NTOGGLE * this, int x, int y, unsigned int b)
{
   if (b & GR_BUTTON_L) {
      this->pressed = 1;
      n_toggle_setstate(this,1);
   }
}

INIT_NCLASS(radio,toggle)

  /* Initialize the proper method slots with new and overridden methods */
  NMETHOD(radio,init,radio_init);
  NMETHOD(radio,connect,radio_connect);

  NMETHOD(toggle,setstate,radio_setstate);
  NMETHOD(toggle,paintstate,radio_paintstate);

  NMETHOD(widget,buttondown,radio_buttondown);

  NMETHOD(object,cleanup,radio_cleanup);
END_INIT
