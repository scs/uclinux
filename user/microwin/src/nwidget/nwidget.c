/*
 * NanoWidgets v0.2
 * (C) 1999 Screen Media AS
 * 
 * Written by Vidar Hokstad
 * 
 * Contains code from The Nano Toolkit,
 * (C) 1999 by Alexander Peuchert.
 * 
 * In theory, only the widget class should depend on the underlying windowing
 * system. In practice, bitmap formats etc. may also end up being system
 * specific, though.
 */

#include <stdio.h>
#include <nwidgets.h>

static NWIDGET * infocus = 0;
static GR_GC_ID __defaultGC = -1;
static NRENDER * __defaultRenderob = 0; /* FIXME, not implemented yet */

typedef struct {
  NWIDGET * wid;
  GR_WINDOW_ID win;
} _lookup_struct;

#define LOOKUP_SIZE 256

_lookup_struct _table[LOOKUP_SIZE];

static NWIDGET * n_win2widget (GR_WINDOW_ID win)
{
  int i;

  for (i = 0; i < LOOKUP_SIZE; i++) {
    if (_table[i].win == win) {
      /* widget found */
      return _table[i].wid;
    }
  }
  /* widget not found */
  return (NWIDGET *)0;
}

static short n_lookup_init ()
{
  memset (_table, 0, sizeof (_lookup_struct) * LOOKUP_SIZE);
  return 0;
}

static short n_lookup_add_widget (NWIDGET * wid)
{
  int i;
  for (i = 0; i < LOOKUP_SIZE; i++) {
    if (! _table[i].wid) {
      /* found free row */
      _table[i].wid = wid;
      _table[i].win = wid->id;
      return 0;
    }
  }
  /* no free row found */
  return -1;
}

static short n_lookup_remove_widget (NWIDGET * wid)
{
  int i;

  for (i = 0; i < LOOKUP_SIZE; i++) {
    if (_table[i].wid == wid) {
      /* widget found */
      _table[i].wid = (NWIDGET *)0;
      _table[i].win = 0;
      return 0;
    }
  }
  /* widget not found */
  return -1;
  
  return 0;
}

static int widget_isinfocus (NWIDGET * this)
{
   return this->infocus;
}

static void widget_leavefocus (NWIDGET * this)
{
   this->infocus = 0;
   n_widget_repaint(this);
}

static void widget_setfocus (NWIDGET * this)
{
   
   if (infocus) n_widget_leavefocus(infocus);
   infocus = this;
   if (this) this->infocus = 1;
}

static int widget_init (NWIDGET * this, NWIDGET * parent)
{
   //printf("widget_init\n");

   if (n_object_init(this)) return -1;

   this->parent = parent;
   this->sibling = 0;
   this->children = 0;
   
   this->x = 50;
   this->y = 50;
   this->w = 150;
   this->h = 150;

   this->shown = 0;
   n_widget_setfocus(this);
   
   this->id = -1;

   if (parent)  {
      this->gc = parent->gc;
      this->renderob = parent->renderob;
      this->layout = parent->layout;
   } else {
      this->gc = __defaultGC;
      this->renderob = (NOBJECT *) __defaultRenderob;
      this->layout = 0; /* FIXME */
   }
   
   /* Realize windows */
   if (this->parent) {
      /* widget has a parent */
      this->id = GrNewWindow(((NWIDGET *)this->parent)->id,this->x, this->y, this->w, this->h, 0, 0 , 2);
   } else {
      /* widget has no parent -> it's some kind of root widget */
      this->id = GrNewWindow(GR_ROOT_WINDOW_ID,this->x, this->y, this->w, this->h, 0, 6 , 15);
   }

   /* Add widget to window id -> widget lookup table */
   n_lookup_add_widget(this);

   /* Attach this widget to the parent structure as a child */
   if (parent) n_widget_attach(parent,this);
   
   //printf("Widget id = %d\n",this->id);
   if (this->id == -1) {
      fprintf(stderr,"Unable to open window \n");
   }
   
   /* FIXME: This is inefficient. Should at the VERY LEAST let the widgets that need mouse motion/mouse position
    * events request them, instead of enabling those for all widgets
    */
   GrSelectEvents(this->id, GR_EVENT_MASK_EXPOSURE | GR_EVENT_MASK_MOUSE_MOTION | GR_EVENT_MASK_MOUSE_POSITION |
		  GR_EVENT_MASK_BUTTON_DOWN | GR_EVENT_MASK_BUTTON_UP | GR_EVENT_MASK_MOUSE_MOTION | 
		  GR_EVENT_MASK_KEY_DOWN | GR_EVENT_MASK_CLOSE_REQ); 
   return 0;
}

static void widget_cleanup (NWIDGET * this)
{
#ifdef DEBUG   
   printf ("%p::widget_cleanup()\n",this);
#endif
   
   n_widget_hide(this);
   
   /* Remove widget from the system wide lookup table */
   n_lookup_remove_widget(this);
   
   if (this->id != -1) GrDestroyWindow(this->id);
   this->id = -1;
   
   n_super(object,cleanup,this,(this));
}

static void widget_getgeometry (NWIDGET * this, int * x, int *y, int * w, int * h)
{
   if (x) *x = this->x;
   if (y) *y = this->y;
   if (w) *w = this->w;
   if (h) *h = this->h;
}

static void widget_move (NWIDGET * this, int x, int y)
{
   this->x = x; this->y = y;
   if (this->id != -1) GrMoveWindow(this->id,x,y);
}

static void widget_resize (NWIDGET * this, int w, int h)
{
   this->w = w; this->h = h;
   if (this->id != -1) GrResizeWindow(this->id,w,h);
}

static void widget_fillrect (NWIDGET * this, int x, int y, int w, int h)
{
   if (this->id == -1 || this->shown == NWFALSE) return;
   GrFillRect(this->id,this->gc,x,y,w,h);
}

static void widget_rect (NWIDGET * this, int x, int y, int w, int h)
{
   if (this->id == -1 || this->shown == NWFALSE) return;
   GrRect(this->id,this->gc,x,y,w,h);
}

static void widget_line (NWIDGET * this, int x1, int y1, int x2, int y2)
{
   if (this->id == -1 || this->shown == NWFALSE) return;
   GrLine(this->id,this->gc,x1,y1,x2,y2);
}

static void widget_setfg (NWIDGET * this, GR_COLOR fg)
{
   GrSetGCForeground(this->gc,fg);
}

static void widget_setbg (NWIDGET * this, GR_COLOR bg)
{
   GrSetGCBackground(this->gc,bg);
}

static void widget_setmode (NWIDGET * this, int mode)
{
   GrSetGCMode(this->gc,mode);
}

static void widget_attach (NWIDGET * this, NWIDGET * child)
{
   if (!child || !this) return;
   
   child->sibling = this->children;
   this->children = child;
}

static void widget_repaint (NWIDGET * this)
{
   NWIDGET * tmp;

   MWCOLORVAL border;
   MWCOLORVAL bg;
   
   if (this->id == -1 || this->shown == NWFALSE) return;
   
   /* FIXME: For test only... So I can see my widgets :) */
   bg = n_widget_getrendercol(this,RCOL_WIDGET_BACKGROUND);
   border = n_widget_getrendercol(this,RCOL_WIDGET_DARK);
   
   n_widget_setfg(this, bg);
   n_widget_fillrect(this,0,0,this->w,this->h);
   n_widget_setfg(this, border);
   n_widget_rect(this,0,0,this->w,this->h);

   tmp = this->children;
   while (tmp) {
      n_widget_repaint(tmp);
      tmp = tmp->sibling;
   }
}

static void widget_show (NWIDGET * this)
{
   if (this->id == -1) {
      fprintf (stderr,"   No window to show\n");
      /* widget is not initialized. This is a fatal error... */
      return;
   }

   /* now, map the widget in the server */
   GrMapWindow(this->id);
   this->shown = NWTRUE;
   
   n_widget_repaint(this); 
}

static void widget_hide (NWIDGET * this)
{
   if (this->id == -1) {
      /* widget is not initialized. This is a fatal error... */
      return;
   }

   /* now, unmap the widget in the server */
   GrUnmapWindow(this->id);
   this->shown = NWTRUE;
}

static void widget_buttondown(NWIDGET * this, int x, int y, unsigned int b)
{
   /* FIXME: For test purposes only */
   if (b & GR_BUTTON_R) n_widget_repaint(this);
}

static void widget_buttonup(NWIDGET * this, int x, int y, unsigned int b)
{
}

static void widget_clicked(NWIDGET * this, int x, int y, unsigned int b)
{
}

static void widget_mousemove(NWIDGET * this, int x,int y, unsigned int b)
{
}

static NRENDER * widget_getrenderob(NWIDGET * this)
{
   return (NRENDER *) this->renderob;
}

static MWCOLORVAL widget_getrendercol(NWIDGET * this, int col)
{
   if (!this->renderob) return -1;
   return n_render_getcolor(this->renderob, col);
}

static void widget_text(NWIDGET * this, int x, int y, const char * text, int len)
{
   if (this->id == -1 || this->shown == NWFALSE) return;
   if (!text || len <= 0 || *text == '\0') return;
   GrText(this->id,this->gc,x,y,(char *)text,len, GR_TFASCII|GR_TFBOTTOM);
}

static void widget_textextent(NWIDGET * this, const char * text, int len, int * retw, int * reth, int * retb)
{
   if (!text || len <= 0 || *text == '\0') return;
   GrGetGCTextSize(this->gc,(char *)text,len,0,retw,reth,retb);
}

static void widget_keypress(NWIDGET * this, unsigned int ch, unsigned int modifiers, unsigned int buttons)
{
   //printf("  ch = %c (%x)\n",ch,ch);
   //printf("  modifiers = %x\n",modifiers);
   //printf("  buttons = %x\n",buttons);
}

/* Implement the n_init_widget_class() function */
INIT_NCLASS(widget,object)
  /* Initalize Nano-X, and set up the default GC */

  if (GrOpen() < 0) {
     fprintf(stderr,"Unable to open connection to Nano X\n");
     exit(1);
  }

  __defaultGC = GrNewGC();
  GrSetGCBackground(__defaultGC, BLUE);
  GrSetGCForeground(__defaultGC, GREEN);
  GrSetGCUseBackground(__defaultGC, NWFALSE);
#if 0
#ifdef MWIN
  GrSetGCFont(__defaultGC, GR_FONT_GUI_VAR);
#endif
#endif

  n_init_render_class();
  __defaultRenderob = NEW_NOBJECT(render);
  n_render_init(__defaultRenderob);

  /* Init window id -> widget lookup */
  n_lookup_init();

  /* Initialize the proper method slots with new and overridden methods */
  NMETHOD(widget,init,widget_init);
  NMETHOD(object,cleanup,widget_cleanup);
  NMETHOD(widget,attach,widget_attach); 

  NMETHOD(widget,show,widget_show); 
  NMETHOD(widget,hide,widget_hide); 
  NMETHOD(widget,repaint,widget_repaint);

  NMETHOD(widget,fillrect,widget_fillrect);
  NMETHOD(widget,rect,widget_rect);
  NMETHOD(widget,line,widget_line);
  NMETHOD(widget,setfg,widget_setfg);
  NMETHOD(widget,setbg,widget_setbg);
  NMETHOD(widget,setmode,widget_setmode);
  NMETHOD(widget,move,widget_move);
  NMETHOD(widget,resize,widget_resize);
  NMETHOD(widget,getgeometry,widget_getgeometry);

  NMETHOD(widget,buttonup,widget_buttonup);
  NMETHOD(widget,buttondown,widget_buttondown);
  NMETHOD(widget,mousemove,widget_mousemove);
  NMETHOD(widget,clicked,widget_clicked);
  NMETHOD(widget,keypress,widget_keypress);

  NMETHOD(widget,setfocus,widget_setfocus);
  NMETHOD(widget,leavefocus,widget_leavefocus);
  NMETHOD(widget,isinfocus,widget_isinfocus);

  NMETHOD(widget,text,widget_text);
  NMETHOD(widget,textextent,widget_textextent);

  NMETHOD(widget,getrendercol,widget_getrendercol);
  NMETHOD(widget,getrenderob,widget_getrenderob);
END_INIT

void n_handle_event (void) 
{
   GR_EVENT event;          /* current event */
   NWIDGET * evw;
      
   GrGetNextEvent(&event);

   evw = n_win2widget(event.general.wid);
      
   switch (event.type) {
    case GR_EVENT_TYPE_CLOSE_REQ:	/* FIXME: the app should handle this */
      GrClose();
      exit(0);
    case GR_EVENT_TYPE_KEY_DOWN:
      n_widget_keypress(infocus,event.keystroke.ch,event.keystroke.modifiers,event.keystroke.buttons);
      break;
    case GR_EVENT_TYPE_MOUSE_MOTION:
//    case GR_EVENT_TYPE_MOUSE_POSITION:
      evw = n_win2widget(event.mouse.wid);
      if (evw) {
	 //fprintf(stderr,"mouse.x = %d, mouse.y = %d, mouse.buttons = %d\n",event.mouse.x,event.mouse.y, event.mouse.buttons);
	 n_widget_mousemove(evw,event.mouse.x,event.mouse.y,event.mouse.buttons);
      }
      break;
    case GR_EVENT_TYPE_EXPOSURE:
      if (evw) n_widget_repaint(evw);
      break;
    case GR_EVENT_TYPE_BUTTON_UP:
      evw = n_win2widget(event.button.subwid);
      if (evw) {
	 /* FIXME: This does not work as planned. We may have to track focus */
	 if (event.button.subwid == event.general.wid) {
	    n_widget_clicked(evw,event.button.x,event.button.y,event.button.changebuttons);
	 } else n_widget_buttonup(evw,event.button.x,event.button.y,event.button.changebuttons);
      }
      break;
    case GR_EVENT_TYPE_BUTTON_DOWN:
      evw = n_win2widget(event.button.subwid);
      if (evw) {
	 n_widget_setfocus(evw);
	 n_widget_buttondown(evw,event.button.x,event.button.y,event.button.changebuttons);
      }

      break;
   }
}
