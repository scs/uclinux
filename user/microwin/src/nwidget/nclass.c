/*
 * NanoClasses v0.1
 * (C) 1999 by Screen Media
 * 
 * Minimal toolkit to build a C based class hierarchy
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <nclass.h>

struct object_nclass __object_nclass;

static int __object_init (NOBJECT * this) {
   //printf("__object_init\n");
   return 0;
}

static void __object_cleanup (NOBJECT * this) {
   //printf("__object_cleanup\n");
}

void n_init_object_class (void) {
   struct object_nclass * this = &__object_nclass;
   __object_nclass.__super = 0;
   
   NMETHOD(object,init,__object_init);
   NMETHOD(object,cleanup,__object_cleanup);
}

/* Create new objects, given a class pointer, and the size of the object. *DO NOT CALL DIRECTLY*
 * Use NEW_NOBJECT(classname) instead.
 */

NOBJECT * n_new_object(NCLASS * c, int size)
{
   NOBJECT * tmp;
   
   tmp = (NOBJECT *)calloc(1,size);
   if (!tmp) return 0;
   tmp->__class = c;
   return tmp;
}

void n_delete_object(NOBJECT * ob)
{
   if (!ob) return;
   n_object_cleanup(ob);
   free(ob);
}
