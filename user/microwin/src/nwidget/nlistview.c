#include <stdlib.h>
#include <nwidgets.h>

/* listview_resize()
 * Used by addentry and addentries to resize the list array if this->maxentries are exceeded.
 * Can also be used to trim the list in size.
 */

/* PRIVATE (for now) */
static void listview_resize (NLISTVIEW * this, int size, int freeold)
{   
   const char ** ptr;
   int i;
   
   this->maxentries = size;
   size++; /* Make space for terminating 0 */
   
   ptr = this->entries;
   
   this->entries = (const char **) malloc (sizeof (const char *) * size);
   
   i = 0;
   while (ptr[i] && (i < size)) {
      this->entries[i] = ptr[i];
      i++;
   }
   this->numentries = i;
   if (this->topentry > this->numentries) this->topentry = this->numentries;
   this->entries[i] = 0;
   
   /* Free old entries, unless specified otherwise */
   if (ptr && freeold) free(ptr);
}

static void listview_repaint (NLISTVIEW * this)
{
   int w,h;
   
   n_widget_getgeometry(this,0,0,&w,&h);
   n_widget_setfg(this,BLUE);
   n_widget_setbg(this,BLUE);
   n_widget_fillrect(this,0,0,w,h);
   
   /* Draw text... Excpect text clipping
    * If selected line is among the visible ones,
    * highlight.
    */
   
   /* Draw border */

   /* This widget doesnt support scrollbars/sliders. Use the list widget for that */
}

static void listview_init (NLISTVIEW * this, NWIDGET * parent, const char ** entries)
{  
   this->numentries = 0;
   this->maxentries = 0;
   this->selected = -1;
   this->topentry = 0;
   
   this->entries = entries;
   while (*entries) {
      entries++;
      this->numentries++;
   }

   /* Make space, and copy */
   listview_resize(this, this->numentries + 100,0);
}

static void listview_cleanup (NLISTVIEW * this)
{
   if (this->entries) free(this->entries);
   n_super(object,cleanup,this,(this));
}

INIT_NCLASS(listview,widget)
  NMETHOD(listview,init,listview_init);
  NMETHOD(object,cleanup,listview_cleanup);
END_INIT
