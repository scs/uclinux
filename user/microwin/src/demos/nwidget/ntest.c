/*
 * NanoWidgets v0.2
 * (C) 1999 Screen Media AS
 * 
 * Written by Vidar Hokstad
 * 
 * Contains code from The Nano Toolkit,
 * (C) 1999 by Alexander Peuchert.
 *
 */

#include <nwidgets.h>

#include <stdio.h>
#include <string.h>
#if UNIX
#include <unistd.h>
#endif

/****************** Test ****************************************/

void onclick(NBUTTON * w, int b)
{
   printf("Button %d was clicked in widget %p\n",b,w);
}

int main ()
{
   NWIDGET * w;
   NWIDGET * w2;
   
   NBUTTON * b1;
   NBUTTON * b2;
   NBUTTON * b3;
   NTOGGLE * b4;

   NSLIDER * s;

   NRADIO * r1;
   NRADIO * r2;

   NTEXTFIELD * t;

   n_init_button_class();
   n_init_slider_class();
   n_init_toggle_class();
   n_init_radio_class();
   n_init_textfield_class();

#ifndef MWIN
   sleep(2);
#endif
   
   w = NEW_NOBJECT(widget);
   w2 = NEW_NOBJECT(widget);

   b1 = NEW_NOBJECT(button);
   b2 = NEW_NOBJECT(button);
   b3 = NEW_NOBJECT(button);
   b4 = NEW_NOBJECT(toggle);
   
   s = NEW_NOBJECT(slider);
   
   r1 = NEW_NOBJECT(radio);
   r2 = NEW_NOBJECT(radio);
   
   t = NEW_NOBJECT(textfield);
   
   n_widget_init(w,0);   
   n_widget_resize(w,300,200);
   n_widget_show(w);
   
   n_widget_init(w2,0);   
   n_widget_move(w2,300,300);
   n_widget_resize(w2,400,300);
   n_widget_show(w2);

   n_button_init(b1,w,"text1");
   n_widget_resize(b1,30,30);
   n_button_onclick(b1,onclick);
   n_widget_show(b1);
   
   n_button_init(b2,w2,"test");
   n_widget_resize(b2,30,30);
   n_button_onclick(b2,onclick);
   n_widget_show(b2);

   n_button_init(b3,w,"label");
   n_widget_move(b3,10,10);
   n_widget_resize(b3,60,30);
   n_button_onclick(b3,onclick);
   n_widget_show(b3);
   
   n_toggle_init(b4,w);
   n_widget_move(b4,10,90);
   n_widget_resize(b4,15,15);
   n_widget_show(b4);

   n_slider_init(s,w);
   n_widget_move(s,200,100);
   n_widget_resize(s,100,100);
   n_widget_show(s);
   
   n_radio_init(r1,w2);
   n_widget_move(r1,20,20);
   n_widget_resize(r1,20,20);
   n_widget_show(r1);
   
   n_radio_init(r2,w2);
   n_widget_move(r2,45,20);
   n_widget_resize(r2,20,20);
   n_radio_connect(r1,r2);
   n_widget_show(r2);

   n_textfield_init(t,w2,"This is my text");
   n_widget_move(t,45,100);
   n_widget_resize(t,200,20);
   n_widget_show(t);

   n_main();

   n_widget_hide(w);
   n_object_cleanup(w);
   
   GrClose();
}
