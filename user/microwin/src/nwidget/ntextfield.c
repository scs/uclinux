#include <stdlib.h>
#include <string.h>
#include <nwidgets.h>

/* PRIVATE */
static void textfield_drawcursor (NTEXTFIELD * this, int h)
{
   int th,tw,tb;
   if (h == 0) n_widget_getgeometry(this,0,0,0,&h);   
   n_widget_setfg(this,GRAY);
   if (this->curpos > this->firstpos)
     n_widget_textextent(this,this->textbuf + this->firstpos,this->curpos - this->firstpos,&tw,&th,&tb);
   else tw = 0;
   n_widget_setmode(this,GR_MODE_XOR); 
   n_widget_line(this,2+tw,2,2+tw,h-2);
   n_widget_setmode(this,GR_MODE_SET); 
}

static void textfield_repaint (NTEXTFIELD * this)
{
   int w,h;
   int th,tw,tb,len;
   NRENDER * rob;
   
   rob = n_widget_getrenderob(this);
   n_widget_getgeometry(this,0,0,&w,&h);
   
   n_widget_setfg(this,LTGRAY);
   n_widget_setbg(this,LTGRAY);
   n_widget_fillrect(this,1,1,w-2,h-2);

   n_widget_setfg(this,1);

   len = strlen(this->textbuf + this->firstpos);

   tw = th = tb = 0;
   n_widget_textextent(this,this->textbuf + this->firstpos,len,&tw,&th,&tb);

//   if (tw > w) printf("tw > w: tw = %d, w = %d\n",tw,w);
   /* FIXME: Ugly and slow */
   while (tw > w) {
      len--;
      n_widget_textextent(this,this->textbuf + this->firstpos,len,&tw,&th,&tb);
   }
//   n_widget_text(this,2,h - 2 - tb,this->textbuf+this->firstpos,len);
   n_widget_text(this,2, tb + 4,this->textbuf+this->firstpos,len);

   if (n_widget_isinfocus(this)) textfield_drawcursor(this,h);

   n_render_border(rob,this,0,0,w,h,1);
}

static void textfield_settext (NTEXTFIELD * this, const char * text)
{   
   int maxsize;

   if (text && strlen(text) > 256) maxsize = strlen(text) + 1;
   else maxsize = 256;

   if (this->maxsize < maxsize) {
      if (this->textbuf) free(this->textbuf);
      if ((this->textbuf = malloc(maxsize))) {
	 this->textbuf[0] = '\0';
	 this->maxsize = maxsize;
      } else this->maxsize = 0;
   }
   
   if (!this->textbuf) free(this->textbuf);
   if (text) this->textbuf = strdup(text);
   else this->textbuf = 0;

   if (text && this->textbuf) strcpy(this->textbuf,text);
   this->curpos = 0;
   this->firstpos = 0;
   
   n_widget_repaint(this);

}

static void textfield_cleanup (NTEXTFIELD * this)
{

   if (this->textbuf) free(this->textbuf);
   n_super(object,cleanup,this,(this));
}

static int textfield_init (NTEXTFIELD * this, NWIDGET * parent, const char * text)
{
   if (n_widget_init(this,parent)) return -1;

   /* FIXME: Should use n_textfield_settext */

   textfield_settext(this,text);

   return 0;
}

static void textfield_buttondown(NTEXTFIELD *this, int x, int y, unsigned int b)
{
   int len;
   int tw,th,tb;
   
   if (!this->textbuf) this->curpos = 0;
   else {
      /* FIXME: Do real calculation... This is *UGLY* */
      this->curpos = this->firstpos;
      tw = 0;
      while(tw < x) {
	 n_widget_textextent(this,this->textbuf + this->firstpos,this->curpos + 1 - this->firstpos,&tw,&th,&tb);
	 this->curpos++;
      }
      this->curpos -= 1;      
      
      len = strlen(this->textbuf);
      if (this->curpos > len) this->curpos = len;
   }
   n_widget_repaint(this);
}

/* PRIVATE */
/* Adjust this->firstpos so that this->curpos is always visible
 * FIXME: Currently this entire function is one *HUGE* hack. Should really
 * cache the last visible position, and use that, and recalc that when
 * firstpos is changed.
 */
static int textfield_adjustfirstpos(NTEXTFIELD * this)
{
   int w,h;
   int th,tw,tb,len;
   
   if (this->curpos <= this->firstpos) {
      this->curpos = this->firstpos;
      return 0;
   }
   
   n_widget_getgeometry(this,0,0,&w,&h);

   len = this->curpos - this->firstpos;

   tw = th = tb = 0;
   n_widget_textextent(this,this->textbuf + this->firstpos,len,&tw,&th,&tb);

   if (tw < (w-8)) return 0;
   while (len>0 && tw > (w-8)) {
      this->firstpos++;
      len--;
      n_widget_textextent(this,this->textbuf + this->firstpos,len,&tw,&th,&tb);
   }
   return 1;
}

/* FIXME: Clean this up... Logic is way too convoluted.
 * This will also need to be improved to handle Unicode text in the future.
 */
static void textfield_keypress(NTEXTFIELD * this, int ch, unsigned int modifiers, unsigned int buttons)
{
   unsigned char c = (unsigned char) ch;
   //fprintf(stderr,"   ch = %c / %x\n   modifiers = %x\n",ch,ch,modifiers);
   if (this->textbuf && this->curpos < this->maxsize) {
      /* Erase the cursor if it is tere... */
      if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
      
      /* FIXME: Check modifiers */
      if (this->esc) {
	 if (c == 'D') {
	    if (!this->curpos) {
	       this->esc = 0;
	       if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
	       return;
	    }
	    this->curpos--;
	    this->esc = 0;
	    if (this->curpos < this->firstpos && this->firstpos) this->firstpos--;
	    else {
	       if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
	       return;
	    }
	 } else if (c == 'C') {
	    if (this->textbuf && this->textbuf[this->curpos]) this->curpos++;
	    this->esc = 0;
	    
	    if (textfield_adjustfirstpos(this)) n_widget_repaint(this);
	    else if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
	    return;
	 } else {
	    if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
	    return;
	 }
      } else if (c == 0x01) {  /* CTRL-A  -- Go to beginning */
	 this->curpos = 0;
	 this->firstpos = 0;

      } else if (c == 0x05) {  /* CTRL-E  -- Go to end */
	 this->curpos = strlen(this->textbuf);
	 
	 if (textfield_adjustfirstpos(this)) n_widget_repaint(this);
	 else if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
	 return;
      } else if (c == 0x18) {  /* CTRL-X  -- Delete line */
	 if (this->textbuf) this->textbuf[0] = '\0';
	 this->curpos = 0;
	 this->firstpos = 0;
      } else if (c == 0x1b) {
	 this->esc = 1;
	 if (n_widget_isinfocus(this)) textfield_drawcursor(this,0);
	 return;
      } else if (c == 0x7f) {
	 if (this->textbuf && this->curpos>0) {
	    memmove(this->textbuf + this->curpos-1, this->textbuf + this->curpos, this->maxsize - this->curpos);
	    this->curpos--;
	    if (this->curpos < this->firstpos) this->firstpos--;
	 }
      } else if (c >= 0x20) {
	 if (this->overwrite) {
	    if (this->textbuf[this->curpos] == '\0') this->textbuf[this->curpos+1] = '\0';
	 } else {
	    memmove(this->textbuf + this->curpos + 1, this->textbuf + this->curpos, this->maxsize - this->curpos+1);
	 }
	 this->textbuf[this->curpos] = c;
	 this->curpos++;
	 textfield_adjustfirstpos(this);
      }
      /* FIXME: Use verify handler */
      n_widget_repaint(this);
   }
}

INIT_NCLASS(textfield,widget)
   NMETHOD(textfield,init,textfield_init);
   NMETHOD(object,cleanup,textfield_cleanup);
   NMETHOD(widget,repaint,textfield_repaint);
   NMETHOD(widget,buttondown,textfield_buttondown);
   NMETHOD(widget,keypress,textfield_keypress);
END_NCLASS
