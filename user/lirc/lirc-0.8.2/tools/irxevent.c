/*      $Id: irxevent.c,v 5.19 2007/03/30 07:13:47 lirc Exp $      */

/****************************************************************************
 ** irxevent.c **************************************************************
 ****************************************************************************
 *
 * irxevent  - infra-red xevent sender
 *
 * Heinrich Langos  <heinrich@null.net>
 * small modifications by Christoph Bartelmus <lirc@bartelmus.de>
 *
 * irxevent is based on irexec (Copyright (C) 1998 Trent Piepho)
 * and irx.c (no copyright notice found)
 *
 *  =======
 *  HISTORY
 *  =======
 *
 * 0.1 
 *     -Initial Release
 *
 * 0.2 
 *     -no more XWarpPointer... sending Buttonclicks to off-screen
 *      applications works becaus i also fake the EnterNotify and LeaveNotify
 *     -support for keysymbols rather than characters... so you can use
 *      Up or Insert or Control_L ... maybe you could play xquake than :*)
 *
 * 0.3
 *     -bugfix for looking for subwindows of non existing windows 
 *     -finaly a README file
 *
 * 0.3a (done by Christoph Bartelmus)
 *     -read from a shared .lircrc file 
 *     -changes to comments
 *     (chris, was that all you changed?)
 *
 * 0.4
 *     -fake_timestamp() to solve gqmpeg problems 
 *     -Shift Control and other mod-keys may work. (can't check it right now)
 *      try ctrl-c or shift-Page_up or whatever ...
 *      modifiers: shift, caps, ctrl, alt, meta, numlock, mod3, mod4, scrlock
 *     -size of 'char *keyname' changed from 64 to 128 to allow all mod-keys. 
 *     -updated irxevent.README
 *
 * 0.4.1
 *     -started to make smaller version steps :-)
 *     -Use "CurrentWindow" as window name to send events to the window
 *      that -you guessed it- currently has the focus.
 *
 * 0.4.2
 *     -fixed a stupid string bug in key sending.
 *     -updated irxevent.README to be up to date with the .lircrc format.
 *
 * 0.4.3
 *     -changed DEBUG functions to actually produce some output :)
 *
 * 0.5.0
 *     -fixed finding subwindows recursively
 *     -added xy_Key (though xterm and xemacs still don't like me)
 *     -added compilation patch from Ben Hochstedler 
 *      <benh@eeyore.moneng.mei.com> for compiling on systems 
 * 	without strsep() (like some solaris)
 *
 *
 * see http://www.wh9.tu-dresden.de/~heinrich/lirc/irxevent/irxevent.keys
 * for a the key names. (this one is for you Pablo :-) )
 *
 * for more information see the irxevent.README file
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <sys/time.h>
#include <unistd.h>

#include "lirc_client.h"

static int bDaemon = 0;
static int bInError = 0;

#ifdef DEBUG
static void debugprintf(char *format_str, ...)
{
        va_list ap;
        va_start(ap,format_str);
        if(!bDaemon)
		vfprintf(stderr,format_str,ap);
        va_end(ap);
}
#else
static void debugprintf(char *format_str, ...)
{
}
#endif

struct keymodlist_t {
        char *name;
        Mask mask;
};
static struct keymodlist_t keymodlist[]=
{
  {"SHIFT",   ShiftMask},
  {"CAPS",    LockMask},
  {"CTRL",    ControlMask},
  {"ALT",     Mod1Mask},{"META",    Mod1Mask},
  {"NUMLOCK", Mod2Mask},
  {"MOD3",    Mod3Mask},  /* I don't have a clue what key maps to this. */
  {"MOD4",    Mod4Mask},  /* I don't have a clue what key maps to this. */
  {"SCRLOCK", Mod5Mask},
  {NULL,0},
};

static const char *key_delimiter ="-";
static const char *active_window_name ="CurrentWindow";
static const char *root_window_name ="RootWindow";


static const char *progname="irxevent";
static Display *dpy;
static Window root;
static XEvent xev;
static Window w,subw;

static Time fake_timestamp()
     /*seems that xfree86 computes the timestamps like this     */
     /*strange but it relies on the *1000-32bit-wrap-around     */
     /*if anybody knows exactly how to do it, please contact me */
{
  int  tint;
  struct timeval  tv;
  struct timezone tz; /* is not used since ages */
  gettimeofday(&tv,&tz);
  tint=(int)tv.tv_sec*1000;
  tint=tint/1000*1000;
  tint=tint+tv.tv_usec/1000;
  return (Time)tint;
}

static Window find_window(Window top,char *name)
{
  char *wname,*iname;
  XClassHint xch;
  Window *children,foo;
  int revert_to_return;
  unsigned int nc;
  if (!strcmp(active_window_name,name)){
    XGetInputFocus(dpy, &foo, &revert_to_return);
    return(foo);
  }  else if (!strcmp(root_window_name,name)){
    return(root);
  }
  /* First the base case */
  if (XFetchName(dpy,top,&wname)){
    if (!strncmp(wname,name,strlen(name)))  {
      XFree(wname);
      debugprintf("found it by wname 0x%x \n",top);
      return(top);  /* found it! */
    };
    XFree(wname);
  };

  if(XGetIconName(dpy,top,&iname)){
    if (!strncmp(iname,name,strlen(name)))  {
      XFree(iname);
      debugprintf("found it by iname 0x%x \n",top);
      return(top);  /* found it! */
    };
    XFree(iname);
  };

  if(XGetClassHint(dpy,top,&xch))  {
    if(!strcmp(xch.res_class,name))  {
      XFree(xch.res_name); XFree(xch.res_class);
      debugprintf("res_class '%s' res_name '%s' 0x%x \n", xch.res_class,xch.res_name,top);
      return(top);  /* found it! */
    };
    if(!strcmp(xch.res_name,name))  {
      XFree(xch.res_name); XFree(xch.res_class);
      debugprintf("res_class '%s' res_name '%s' 0x%x \n", xch.res_class,xch.res_name,top);
      return(top);  /* found it! */
    };
    XFree(xch.res_name); XFree(xch.res_class);
  };

  if(!XQueryTree(dpy,top,&foo,&foo,&children,&nc) || children==NULL) {
    return(0);  /* no more windows here */
  };

  /* check all the sub windows */
  for(;nc>0;nc--)  {
    top = find_window(children[nc-1],name);
    if(top) break;  /* we found it somewhere */
  };
  if(children!=NULL) XFree(children);
  return(top);
}

static Window find_sub_sub_window(Window top,int *x, int *y)
{
  Window base;
  Window *children,foo,target=0;
  unsigned int nc,
    rel_x,rel_y,width,height,border,depth,
    new_x=1,new_y=1,
    targetsize=1000000;

  base=top;
  if (!base) {return base;};
  if(!XQueryTree(dpy,base,&foo,&foo,&children,&nc) || children==NULL) {
    return(base);  /* no more windows here */
  };
  debugprintf("found subwindows %d\n",nc);

  /* check if we hit a sub window and find the smallest one */
  for(;nc>0;nc--)  {
    if(XGetGeometry(dpy, children[nc-1], &foo, &rel_x, &rel_y, 
		    &width, &height, &border, &depth)){
      if ((rel_x<=*x)&&(*x<=rel_x+width)&&(rel_y<=*y)&&(*y<=rel_y+height)){
	debugprintf("found a subwindow 0x%x +%d +%d  %d x %d   \n",children[nc-1], rel_x,rel_y,width,height);
	if ((width*height)<targetsize){
	  target=children[nc-1];
	  targetsize=width*height;
	  new_x=*x-rel_x;
	  new_y=*y-rel_y;
	  /*bull's eye ...*/
	  target=find_sub_sub_window(target,&new_x,&new_y);
	}
      }	
    }
  };
  if(children!=NULL) XFree(children);
  if (target){
    *x=new_x;
    *y=new_y;
    return target;
  }else
    return base;
}



static Window find_sub_window(Window top,char *name,int *x, int *y)
{
  Window base;
  Window *children,foo,target=0;
  unsigned int nc,
    rel_x,rel_y,width,height,border,depth,
    new_x=1,new_y=1,
    targetsize=1000000;

  base=find_window(top, name);
  if (!base) {return base;};
  if(!XQueryTree(dpy,base,&foo,&foo,&children,&nc) || children==NULL) {
    return(base);  /* no more windows here */
  };
  debugprintf("found subwindows %d\n",nc);

  /* check if we hit a sub window and find the smallest one */
  for(;nc>0;nc--)  {
    if(XGetGeometry(dpy, children[nc-1], &foo, &rel_x, &rel_y, 
		    &width, &height, &border, &depth)){
      if ((rel_x<=*x)&&(*x<=rel_x+width)&&(rel_y<=*y)&&(*y<=rel_y+height)){
	debugprintf("found a subwindow 0x%x +%d +%d  %d x %d   \n",children[nc-1], rel_x,rel_y,width,height);
	if ((width*height)<targetsize){
	  target=children[nc-1];
	  targetsize=width*height;
	  new_x=*x-rel_x;
	  new_y=*y-rel_y;
	  /*bull's eye ...*/
	  target=find_sub_sub_window(target,&new_x,&new_y);
	}
      }	
    }
  };
  if(children!=NULL) XFree(children);
  if (target){
    *x=new_x;
    *y=new_y;
    return target;
  }else
    return base;
}


static Window find_window_focused(Window top,char *name) 
{
  int tmp;
  Window w, cur, *children, foo;
  unsigned int n;

 
  /* return the currently focused window if it is a direct match or a
     subwindow of the named window */

  if((w=find_window(top,name))) {
    XGetInputFocus(dpy, &cur, &tmp);
    debugprintf("current window: 0x%x named window: 0x%x\n",cur,w);

    if( w == cur ) {
      /* window matched */
      return(cur);
    } 
    else if(XQueryTree(dpy,w,&foo,&foo,&children,&n) && children!=NULL) {
      /* check all the sub windows of named window */
      for(;n>0;n--)  {
	if(children[n-1] == cur ) {
	  XFree(children);
	  return(cur);
	}
      }
      XFree(children);
    } 
  }
  
  return(0);
}

static void make_button(int button,int x,int y,XButtonEvent *xev)
{
  xev->type = ButtonPress;
  xev->display=dpy;
  xev->root=root;
  xev->subwindow=None;
  xev->time=fake_timestamp();
  xev->x=x;xev->y=y;
  xev->x_root=1; xev->y_root=1;
  xev->state=0;
  xev->button=button;
  xev->same_screen=True;

  return;
}

static void make_key(char *keyname,int x, int y,XKeyEvent *xev)
{
  char *part, *part2, *sep_part;
  struct keymodlist_t *kmlptr;
  KeySym ks;
  KeyCode kc;

  part2=malloc(128);

  xev->type = KeyPress;
  xev->display=dpy;
  xev->root=root;
  xev->subwindow = None;
  xev->time=fake_timestamp();
  xev->x=x; xev->y=y;
  xev->x_root=1; xev->y_root=1;
  xev->same_screen = True;

  xev->state=0;
#ifdef HAVE_STRSEP
  while ((part=strsep(&keyname, key_delimiter)))
#else
  while ((part=strtok(keyname, key_delimiter)) && ((keyname=NULL)==NULL))
#endif
    {
      part2=strncpy(part2,part,128);
      //      debugprintf("-   %s \n",part);
      kmlptr=keymodlist;
      while (kmlptr->name)
	{
	  //	  debugprintf("--  %s %s \n", kmlptr->name, part);
	  if (!strcasecmp(kmlptr->name, part))
	    xev->state|=kmlptr->mask;
	  kmlptr++;
	}
      //      debugprintf("--- %s \n",part);
    } 
  //  debugprintf("*** %s \n",part);
  //  debugprintf("*** %s \n",part2);

  /*
   * New code 14-June-2005 by Warren Melnick, C.A.C. Media
   * Uses the KeySym: and KeyCode: prefixes on the Key lines to allow for
   * numeric keysym and keycode numbers to be used in place of X keysyms.
   * Example 1: config = Key KeyCode:127 CurrentWindow
   * Example 2: config = Key KeySym:0xFFF0 CurrentWindow
   */
  ks = 0;
  kc = 0;
  if (strncmp(part2, "KeySym:", 7) == 0) {
    sep_part = part2 + 7;
    ks = strtoul(sep_part, NULL, 0);
    kc = XKeysymToKeycode(dpy, ks);
    debugprintf("KeySym String: %s, KeySym: %ld KeyCode: %d\n", part2, ks, kc);
  } else if (strncmp(part2, "KeyCode:", 8) == 0) {
    sep_part = part2 + 8;
    kc = (KeyCode) strtoul(sep_part, NULL, 0);
    debugprintf("KeyCode String: %s, KeyCode: %d\n", part2, kc);
  }
  if ((ks == 0) && (kc == 0)) {
    ks = XStringToKeysym(part2);
    kc = XKeysymToKeycode(dpy, ks);
    debugprintf("Unmodified String: %s, KeySym: %d KeyCode: %d\n", part2, ks, kc);
  }
  xev->keycode=kc;
  debugprintf("state 0x%x, keycode 0x%x\n",xev->state, xev->keycode);
  free(part2);
  return ;
}

static void sendfocus(Window w,int in_out)
{
  XFocusChangeEvent focev;

  focev.display=dpy;
  focev.type=in_out;
  focev.window=w;
  focev.mode=NotifyNormal;
  focev.detail=NotifyPointer;
  XSendEvent(dpy,w,True,FocusChangeMask,(XEvent*)&focev);
  XSync(dpy,True);
  
  return;
}

static void sendpointer_enter_or_leave(Window w,int in_out)
{
  XCrossingEvent crossev;
  crossev.type=in_out;
  crossev.display=dpy;
  crossev.window=w;
  crossev.root=root;
  crossev.subwindow=None;
  crossev.time=fake_timestamp();
  crossev.x=1;
  crossev.y=1;
  crossev.x_root=1;
  crossev.y_root=1;
  crossev.mode=NotifyNormal;
  crossev.detail=NotifyNonlinear;
  crossev.same_screen=True;
  crossev.focus=True;
  crossev.state=0;
  XSendEvent(dpy,w,True,EnterWindowMask|LeaveWindowMask,(XEvent*)&crossev);
  XSync(dpy,True);
  return;
}

static void sendkey(char *keyname,int x,int y,Window w,Window s)
{
  make_key(keyname ,x,y,(XKeyEvent*)&xev);
  xev.xkey.window=w;
  xev.xkey.subwindow=s;

  if (s) sendfocus(s,FocusIn);

  XSendEvent(dpy,w,True,KeyPressMask,&xev);
  xev.type = KeyRelease;
  usleep(2000);
  xev.xkey.time = fake_timestamp();
  if (s) sendfocus(s,FocusOut);
  XSendEvent(dpy,w,True,KeyReleaseMask,&xev);
  XSync(dpy,True);
  return;
}

static void sendbutton(int button, int x, int y, Window w,Window s)
{
  make_button(button,x,y,(XButtonEvent*)&xev);
  xev.xbutton.window=w;
  xev.xbutton.subwindow=s;
  sendpointer_enter_or_leave(w,EnterNotify);
  sendpointer_enter_or_leave(s,EnterNotify);

  XSendEvent(dpy,w,True,ButtonPressMask,&xev);
  XSync(dpy,True);
  xev.type = ButtonRelease;
  xev.xkey.state|=0x100;
  usleep(1000);
  xev.xkey.time = fake_timestamp(); 
  XSendEvent(dpy,w,True,ButtonReleaseMask,&xev);
  sendpointer_enter_or_leave(s,LeaveNotify);
  sendpointer_enter_or_leave(w,LeaveNotify);
  XSync(dpy,True);

  return;
}

int errorHandler(Display* di, XErrorEvent* ev)
{
  char buff[512]; buff[0] = 0;
  if(bInError || ev==NULL || di==NULL) return 1;      // only 1 msg per key
  XGetErrorText(di, ev->error_code, buff, sizeof(buff)-1);
  if(buff[0]) {
     if(!bDaemon) fprintf(stderr, "X11 error: %s\n", buff);
     bInError = 1;
  }
  return 1;
}

int check(char *s)
{
  int d;
  char *buffer;

  buffer=malloc(strlen(s));
  if(buffer==NULL)
    {
      fprintf(stderr,"%s: out of memory\n",progname);
      return(-1);
    }

  if(2!=sscanf(s,"Key %s Focus %s %s",buffer,buffer,buffer) &&
     2!=sscanf(s,"Key %s WindowID %i %s",buffer,&d,buffer) &&
     2!=sscanf(s,"Key %s Focus WindowID %i %s",buffer,&d,buffer) &&
     2!=sscanf(s,"Key %s %s %s",buffer,buffer,buffer) &&
     4!=sscanf(s,"Button %d %d %d Focus %s %s",&d,&d,&d,buffer,buffer) &&
     4!=sscanf(s,"Button %d %d %d WindowID %i %s",&d,&d,&d,&d,buffer) &&
     4!=sscanf(s,"Button %d %d %d Focus WindowID %i %s",&d,&d,&d,&d,buffer) &&
     4!=sscanf(s,"Button %d %d %d %s %s",&d,&d,&d,buffer,buffer) &&
     4!=sscanf(s,"xy_Key %d %d %s Focus %s %s",&d,&d,buffer,buffer,buffer) &&
     4!=sscanf(s,"xy_Key %d %d %s WindowID %i %s",&d,&d,buffer,&d,buffer) &&
     4!=sscanf(s,"xy_Key %d %d %s Focus WindowID %i %s",&d,&d,buffer,&d,buffer) &&
     4!=sscanf(s,"xy_Key %d %d %s %s",&d,&d,buffer,buffer))
    {
      fprintf(stderr,"%s: bad config string \"%s\"\n",progname,s);
      free(buffer);
      return(-1);
    }
  free(buffer);  
  return(0);
}

static struct option long_options[] =
{
	{"daemon",  no_argument, NULL, 'd'},
	{"help",    no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
  char keyname[128];
  int pointer_button,pointer_x,pointer_y;
  char windowname[64];
  struct lirc_config *config;
  char *config_file=NULL;
  int c;
  int WindowID;

  while ((c = getopt_long(argc, argv, "dhV", long_options, NULL)) != EOF) {
    switch (c) {
    case 'd':
      bDaemon = 1; continue;
    case 'h':
      printf("Usage: %s [option]... [config file]\n"
             "       -d --daemon     fork and run in background\n"
             "       -h --help       display usage summary\n"
             "       -V --version    display version\n", progname);
      return(EXIT_SUCCESS);
    case 'V':
      printf("%s %s\n", progname, VERSION);
      return(EXIT_SUCCESS);
    case '?':
      fprintf(stderr, "unrecognized option: -%c\n", optopt);
      fprintf(stderr, "Try `%s --help' for more information.\n", progname);
      return(EXIT_FAILURE);
    }
  }
  
  if (argc == optind+1){
    config_file = argv[optind];
  } else if (argc > optind+1){
    fprintf(stderr, "%s: incorrect number of arguments.\n", progname);
    fprintf(stderr, "Try `%s --help' for more information.\n", progname);
    return(EXIT_FAILURE);
  }

  dpy=XOpenDisplay(NULL);
  if(dpy==NULL) {
    fprintf(stderr,"Can't open DISPLAY.\n");
    exit(1);
  }
  root=RootWindow(dpy,DefaultScreen(dpy));

  // windows may get closed at wrong time. Override default error handler...
  XSetErrorHandler(errorHandler);
  
  if(lirc_init("irxevent",1)==-1) exit(EXIT_FAILURE);

  if(lirc_readconfig(config_file,&config,check)==0)
    {
      char *ir;
      char *c;
      int ret;

      if(bDaemon) {
	if(daemon(1, 0) < 0) {
	  perror("Failed to run as daemon");
	  exit(EXIT_FAILURE);
        }
      }
      
      while(lirc_nextcode(&ir)==0)
	{
	  if(ir==NULL) continue;
	  while((ret=lirc_code2char(config,ir,&c))==0 && c!=NULL)
	    {
	      debugprintf("Received code: %s Sending event: \n",ir);
	      bInError = 0;   // reset error state, want to see error msg
	      
	      *windowname=0;
	      if(2==sscanf(c,"Key %s Focus WindowID %i",keyname,&WindowID) ||
		 4==sscanf(c,"Button %d %d %d Focus WindowID %i",&pointer_button,&pointer_x,&pointer_y,&WindowID) ||
		 4==sscanf(c,"xy_Key %d %d %s Focus WindowID %i",&pointer_x,&pointer_y,keyname,&WindowID) ||
		 2==sscanf(c,"Key %s Focus %s",keyname,windowname) ||
		 4==sscanf(c,"Button %d %d %d Focus %s",&pointer_button,&pointer_x,&pointer_y,windowname) ||
		 4==sscanf(c,"xy_Key %d %d %s Focus %s",&pointer_x,&pointer_y,keyname,windowname))
	      {
		debugprintf("Focus\n");
		/* focussed ? */
		if(*windowname) {
		  WindowID=find_window_focused(root,windowname);
		  if(!WindowID) {
		    debugprintf("target window '%s' doesn't have focus\n",windowname);
		    continue;
		  }
		  debugprintf("focused:  %s\n",windowname);
		} else {
		  Window cur;
		  int tmp;
		  
		  XGetInputFocus(dpy, &cur, &tmp);
		  if(WindowID != cur) {
		    debugprintf("target window '0x%x' doesn't have focus\n",WindowID);
		    continue;
		  }
		  debugprintf("focused:  0x%x\n",WindowID);
		}
	      } else if(2==sscanf(c,"Key %s WindowID %i",keyname,&WindowID) ||
			4==sscanf(c,"Button %d %d %d WindowID %i",&pointer_button,&pointer_x,&pointer_y,&WindowID) ||
			4==sscanf(c,"xy_Key %d %d %s WindowID %i",&pointer_x,&pointer_y,keyname,&WindowID)) {
		debugprintf("WindowID:  0x%x\n",WindowID);
		/* WindowID passed */
	      } else if(2==sscanf(c,"Key %s %s",keyname,windowname) || 
			4==sscanf(c,"Button %d %d %d %s",&pointer_button,&pointer_x,&pointer_y,windowname) ||
			4==sscanf(c,"xy_Key %d %d %s %s\n",&pointer_x,&pointer_y,keyname,windowname)) {
		debugprintf("name: %s\n",windowname);
		WindowID=find_window(root,windowname);
		if(WindowID == 0)
		{
		  debugprintf("target window '%s' not found\n", windowname);
		  continue;
		}
	      }
	      
	      switch(c[0])
	      {
	      case 'K': // Key
		debugprintf("keyname: %s \t WindowID: 0x%x\n",keyname,WindowID);
		debugprintf("%s\n",c);
		sendkey(keyname,1,1,(Window)WindowID,0);
		break;
		
	      case 'B': // Button
	      case 'x': // xy_Key
		subw=find_sub_window(root,windowname,&pointer_x,&pointer_y);
		if(subw) {
		  if (WindowID==subw) subw=0;
		  debugprintf("%s\n",c);
		  switch(c[0])
		  {
		  case 'B':
		    sendbutton(pointer_button,pointer_x,pointer_y,WindowID,subw);
		    break;
		  case 'x':
		    sendkey(keyname,pointer_x,pointer_y,WindowID,subw);
		    break;
		  }
		}
		break;
		
	      }
	    }
	  free(ir);
	  if(ret==-1) break;
	}
      lirc_freeconfig(config);
    }
  
  lirc_deinit();
  
  exit(0);
}
