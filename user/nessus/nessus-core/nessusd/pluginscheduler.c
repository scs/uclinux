/* Nessus
 * Copyright (C) 1998 - 2003 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 * pluginscheduler.c : 
 *  Tells nessusd which plugin should be executed now
 *
 */
 
#include <includes.h>
#define IN_SCHEDULER_CODE 1
#include "pluginscheduler.h"
#include "pluginload.h"
#include "pluginlaunch.h"


#define HASH_MAX 2713



int plugin_get_running_state(struct arglist * plugin)
{
 return (int)arg_get_value(plugin, "RUNNING_STATE");
}

void plugin_set_running_state(struct arglist * plugin, int state)
{
 if(plugin == NULL)
  return;
  
 if(arg_get_value(plugin, "RUNNING_STATE") != NULL)
  arg_set_value(plugin, "RUNNING_STATE", sizeof(state), (void*)state);
 else 
  arg_add_value(plugin, "RUNNING_STATE", ARG_INT, sizeof(state), (void*)state);
}

/*-----------------------------------------------------------------------------*/


static int mkhash(char * name)
{
  int l = strlen(name);
  int i;
  int h = 0;
  
  for(i=0;i<l;i++)
   h = ((h * 128) + name[i]) % HASH_MAX;
   
 
  return h < 0 ? -h:h;
}

/*------------------------------------------------------------------------------*/


struct name_cache {
	char * name;
	int occurences;
	struct name_cache * next;
	struct name_cache * prev;
	};

static struct name_cache cache[HASH_MAX + 1];
static int cache_inited = 0;

static void cache_init()
{
 bzero(cache, sizeof(cache));
 cache_inited = 1;
}

static struct name_cache * 
cache_get_name(name)
 char * name;
{
 struct name_cache * nc;
 int h;
 
 if(cache_inited == 0)cache_init();
 
 if(!name)
  return NULL;
  
 h = mkhash(name);
 nc = cache[h].next;
 
 
 while(nc != NULL)
 {
  if(nc->name != NULL && 
    !strcmp(nc->name, name))return nc;
  else 
  	nc = nc->next;
 }
 return NULL;
}

static struct name_cache *
cache_add_name(name)
 char * name;
{
 struct name_cache * nc;
 int h;
 
 if(name == NULL)
  return NULL;
 
 h = mkhash(name);
 
 
 
 nc = emalloc(sizeof(struct name_cache));
 nc->name = estrdup(name);
 nc->occurences = 1;
 nc->next = cache[h].next;
 nc->prev = NULL;
 cache[h].next = nc;
 
 return nc;
}

static char *
cache_inc(name)
 char * name;
{
 struct name_cache * nc = cache_get_name(name);
 if(nc != NULL)
  nc->occurences ++;
 else
   nc = cache_add_name(name);  
 return nc->name;
}

static void 
cache_dec(name)
 char * name;
{
 struct name_cache* nc;

 if( name == NULL )
  return;

 nc  = cache_get_name(name);
 if( nc == NULL )
 {
  return;
 }
 
 nc->occurences --;
 if( nc->occurences == 0 )
  {
    int h = mkhash(name);
    efree(&nc->name);

    if( nc->next != NULL)
     nc->next->prev = nc->prev;
     
    if( nc->prev != NULL )
     nc->prev->next = nc->next;
    else
     cache[h].next = nc->next;
  }
}


/*---------------------------------------------------------------------------*
 *
 * A minimalist HASH stucture
 *
 *---------------------------------------------------------------------------*/

	

static struct hash * hash_init()
{
 struct hash * h = emalloc(sizeof(*h) * HASH_MAX + 1);

 return h;
}

static void hash_link_destroy(struct hash * h)
{
 int i;
 if(h == NULL)
  return;
  
 if(h->next != NULL)
  hash_link_destroy(h->next);
 
 if( h->dependencies != NULL )
 {
  for(i=0;h->dependencies[i] != NULL;i++)
  {
   cache_dec(h->dependencies[i]);
  }
  efree(&h->dependencies);
 }
 
 if( h->ports != NULL )
 {
  for(i=0;h->ports[i] != NULL;i++)
  {
   cache_dec(h->ports[i]);
  }
  efree(&h->ports);
 }
 
 efree(&h);
}

static void hash_destroy(struct hash * h)
{
 int i;
 
 for(i=0;i<HASH_MAX;i++)
  {
  hash_link_destroy(h[i].next);
  }
 efree(&h);
}


static int hash_add(struct hash * h, char * name, struct arglist * plugin)
{
 struct hash * l = emalloc(sizeof(struct hash));
 int idx = mkhash(name);
 struct arglist * deps = plug_get_deps(plugin->value);
 struct arglist * ports = plug_get_required_ports(plugin->value);
 int num_deps = 0;
 
 l->plugin = plugin;
 l->name   = name;
 l->next = h[idx].next;
 h[idx].next = l;
 
 if( deps == NULL )
  l->dependencies = NULL;
 else
 {
  struct arglist * al = deps;
  int i = 0;
  while (al->next)
  { 
   num_deps ++;
   al = al->next;
  }
  l->dependencies = emalloc((num_deps + 1) * sizeof(char*));
  al = deps;
  while (al->next != NULL)
  {
   l->dependencies[i++] = cache_inc(al->name);
   l->num_deps ++;
   al = al->next;
  }
  arg_free_all(deps);
 }
 
 if( ports == NULL )
  l->ports = NULL;
 else
  {
   struct arglist * al = ports;
   int num_ports = 0;
   int i = 0;
   while( al->next != NULL )
   {
    num_ports ++;
    al = al->next;
   }
   
   l->ports = emalloc((num_ports + 1) * sizeof(char*));
   al = ports;
   while (al->next != NULL )
   {
    l->ports[i++] = cache_inc(al->name);
    al = al->next;
   }
   arg_free_all(ports);
  }
 return 0;
}



static struct hash * _hash_get(struct hash * h, char * name)
{
 int idx = mkhash(name);
 struct hash * l = h[idx].next;
 while(l != NULL)
 {
  if(strcmp(l->name, name) == 0)
   return l;
  else
   l = l->next;
 }
 return NULL;
}

static struct arglist * hash_get(struct hash * h, char * name)
{
 struct hash * l = _hash_get(h, name);
 if(  l == NULL )
  return NULL;
 else
  return l->plugin;
}

static char ** hash_get_ports(struct hash * h, char * name)
{
 struct hash * l = _hash_get(h, name);
 if( l == NULL)
  return NULL;
 else
  return l->ports;
}


static char ** hash_get_deps(struct hash * h, char * name)
{
 struct hash * l = _hash_get(h, name);
 char ** deps;
 int i;
 
 if( l == NULL )
  return NULL;
 
 if( l->dependencies == NULL )
  return NULL;
 
 /*
  * Check if any of the dependencies have run already, and remove them
  */
 i = 0;
 deps = l->dependencies;
 
#if 0
 while ( deps[i] != NULL )
 {
  p = hash_get(h, deps[i]);
  if(p == NULL)
  	fprintf(stderr, "hash_get_deps(): Error - can't find plugin\n");
  else 
  	{
	 int state = plugin_get_running_state(p->value);
	 if(state == PLUGIN_STATUS_DONE || state ==  PLUGIN_STATUS_DONE_AND_CLEANED)
	 {
	  l->num_deps --;
	  cache_dec(deps[i]);
	  deps[i] = NULL;
	  if(l->num_deps > 0)
	  	memmove(&(deps[i]), &(deps[i+1]), ( l->num_deps - i ) * sizeof(char*));
	  i--;
	 }
	}
  i ++;	
 }
#endif 
 return deps;
}


/*----------------------------------------------------------------------*/

struct plist * pl_get(struct plist * list, char * name)
{
 while(list != NULL)
 {
  if( strcmp(list->name, name) == 0 )
   return list;
  else
   list = list->next;
 }
 return NULL;
}


/*----------------------------------------------------------------------*
 *									*
 * Utilities								*
 *									*
 *----------------------------------------------------------------------*/



void scheduler_mark_running_ports(plugins_scheduler_t sched, struct arglist * plugin)
{
 char ** ports = hash_get_ports(sched->hash, plugin->name);
 int i;
 
 if( ports == NULL )
 	return;
	
 for(i=0; ports[i] != NULL; i ++ )
 {
  struct plist * pl = pl_get(sched->plist, ports[i]);
	
  if(pl != NULL)
   pl->occurences ++;
  else
  {
   pl = emalloc(sizeof(struct plist));
   strncpy(pl->name, ports[i], sizeof(pl->name) - 1);	/* Share cache_inc() ? */
   pl->occurences = 1;
   pl->next = sched->plist;
   if(sched->plist != NULL)
   	sched->plist->prev = pl;
   pl->prev = NULL;
   sched->plist = pl;
  }
 } 
}

void scheduler_rm_running_ports(plugins_scheduler_t sched, struct arglist * plugin)
{
 char ** ports = hash_get_ports(sched->hash, plugin->name);
 int i;

 

 
 if( ports == NULL )
  return;
 
 for (i = 0 ; ports[i] != NULL ; i ++ )
 {
  struct plist * pl = pl_get(sched->plist, ports[i]);
 
	
  if( pl != NULL )
  {
   pl->occurences --;
   if( pl->occurences == 0 )
   {
    if( pl->next != NULL )
     pl->next->prev = pl->prev;
    
    if( pl->prev != NULL )
     pl->prev->next = pl->next;
    else
     sched->plist = pl->next;
    
    efree(&pl);
   }
  }
  else printf("Warning: scheduler_rm_running_ports failed ?! (%s)\n", ports[i]);
 }
}


/*
 * Returns the 'score' of the plugin, which means the number of
 * plugins that are already hammering the port this plugin will
 * hammer too
 */
int scheduler_plugin_score(plugins_scheduler_t sched, struct arglist * plugin)
{
 char ** ports = hash_get_ports(sched->hash, plugin->name);
 int i;
 int score = 0;
 
 if( ports == NULL ) 
  return 0;
 

 for (i = 0; ports[i] != NULL; i ++)
 {
  struct plist * pl = pl_get(sched->plist, ports[i]);
  if(pl != NULL)
  { 
   if(pl->occurences > score)
   	score = pl->occurences;
  }
 } 
 return score;
}


void scheduler_plugin_best_score(plugins_scheduler_t sched, int *bscore, struct arglist ** bplugin, struct arglist * plugin)
{
 int score = scheduler_plugin_score(sched, plugin);

 if(score < *bscore)
 {
  *bscore = score;
  *bplugin = plugin;
 }
}






struct arglist * plugin_next_unrun_dependencie(plugins_scheduler_t sched, char ** dependencies)
{
 struct hash * h = sched->hash;
 int flag = 0;
 int counter = 0;
 int i;
 
 if(dependencies == NULL)
  return NULL;
  
 for(i=0;dependencies[i] != NULL;i++)
  {
   struct arglist * plugin = hash_get(h, dependencies[i]);
   if(plugin != NULL)
   {
    int state = plugin_get_running_state(plugin->value);
    switch(state)
    {
     case PLUGIN_STATUS_UNRUN :
     	{
	char ** deps = hash_get_deps(h, plugin->name);
	struct arglist * ret;
	counter ++;
	if(deps == NULL)
	  return plugin;	
	else
	 {
	 ret = plugin_next_unrun_dependencie(sched, deps);
	 if(ret == NULL)
		return plugin;
	 else 
	 	if( ret == PLUG_RUNNING )
			flag ++;
		else
			return ret;
	 }
     case PLUGIN_STATUS_RUNNING:
     	flag++;
	break;
     case PLUGIN_STATUS_DONE:
     	scheduler_rm_running_ports(sched, plugin);
	plugin_set_running_state(plugin->value, PLUGIN_STATUS_DONE_AND_CLEANED);
	break;
     case PLUGIN_STATUS_DONE_AND_CLEANED:
     	break;
    }
   }
  }
  else fprintf(stderr, "%s could not be found\n", dependencies[i]);
 }
  
  if(flag == 0)
  	return NULL;
  else
  	return PLUG_RUNNING;
}

/*---------------------------------------------------------------------------*/

/*
 * Enables a plugin and its dependencies
 */
static void enable_plugin_and_dependencies(plugins_scheduler_t shed, struct arglist * plugin, char * name)
{
 char ** deps;
 int i;
 
 deps = hash_get_deps(shed->hash, name);

 plug_set_launch(plugin, 1);
 
 if(deps != NULL)
 {
   for(i=0;deps[i] != NULL;i++)
    {
     struct arglist * p;
     p = hash_get(shed->hash, deps[i]);
     if( p != NULL )
       enable_plugin_and_dependencies(shed, p->value, p->name);
     else
       fprintf(stderr, "'%s' depends on '%s' which could not be found\n", name, deps[i]);
     
    }
 }
}

/*---------------------------------------------------------------------------*/

plugins_scheduler_t plugins_scheduler_init(struct arglist * plugins, int autoload)
{
 plugins_scheduler_t ret = emalloc(sizeof(*ret));
 struct arglist * arg;
 int i;
 
 
 
 
 if(plugins == NULL)
  return NULL;
 
 
 /*
  * Fill our lists
  */
  ret->hash = hash_init();
  arg = plugins;
  while(arg->next != NULL)
  {
  struct list * dup;
  struct arglist * args = arg->value;
  int category =  plug_get_category(args);
  
  if(category > ACT_LAST)category = ACT_LAST;
  dup = emalloc(sizeof(struct list));
  dup->name = arg->name;
  dup->plugin = arg;
  dup->prev = NULL;
  dup->next = ret->list[category];
  if(ret->list[category] != NULL)
   ret->list[category]->prev = dup;
  ret->list[category] = dup;
  hash_add(ret->hash, arg->name, arg);
  plugin_set_running_state(arg->value, PLUGIN_STATUS_UNRUN);
  arg = arg->next;
  }
 
 
 if(autoload != 0)
 {
 arg = plugins;
 while(arg->next != NULL)
  {
   if(plug_get_launch(arg->value) != 0)
   	enable_plugin_and_dependencies(ret, arg->value, arg->name);
   arg = arg->next;
  }
 }
 
 
 /* Now, remove the plugins that won't be launched */
 for(i= ACT_FIRST ; i <= ACT_LAST ; i++)
 {
  struct list * l = ret->list[i];
  while (l != NULL )
  {
   if(plug_get_launch(l->plugin->value) == 0)
   {
    struct list * old = l->next;

    if(l->prev != NULL)
      l->prev->next = l->next;
    else
      ret->list[i] = l->next;
	  
	 
	 if(l->next != NULL)
	  l->next->prev = l->prev;

	efree(&l);
	l = old;
	continue;
    }
    l = l->next;
   }
  }
 
 return ret;
}



struct arglist * plugins_scheduler_next(plugins_scheduler_t h)
{
 
 struct list * l;
 int category;
 int running_category = ACT_LAST;
 int flag = 0;
 
 if(h == NULL)
  return NULL;
 
 for(category = ACT_FIRST;category<=ACT_LAST;category++)
 {
 l = h->list[category];
 
 /*
  * Scanners (and DoS) must not be run in parrallel
  */

 if((category == ACT_SCANNER) ||
    (category == ACT_KILL_HOST) ||
    (category == ACT_DENIAL))
    pluginlaunch_disable_parrallel_checks();
 else
    pluginlaunch_enable_parrallel_checks();
  
      
 while(l != NULL)
 {
   int state;
  
  state = plugin_get_running_state(l->plugin->value);
 
  
  switch(state)
  {
   case PLUGIN_STATUS_UNRUN:
    {
    char ** deps = hash_get_deps(h->hash, l->plugin->name);
    
    if(deps != NULL)
    {
     struct arglist * p = plugin_next_unrun_dependencie(h, deps);
     
     switch((int)p)
     {
      case (int)NULL :
      	scheduler_mark_running_ports(h, l->plugin);
        plugin_set_running_state(l->plugin->value, PLUGIN_STATUS_RUNNING);
        return l->plugin;

	 break;
     case (int)PLUG_RUNNING:
        {
	int cat;
     		/* One of the dependencie is still running */
	cat = plug_get_category(l->plugin->value);
	if(cat < running_category)
		running_category = cat;
     	flag ++;
	}
	break;
     default:
        { 
	 /* Launch a dependencie */
	
	 
	 /* Ack - the plugin we depend on is not of the same category - we recast the current
	  * plugin to another (greater) category 
	  */
#if 0	  
		   int c;

	 if((c = plug_get_category(p->value)) != category)
	 {
	  struct arglist * args = l->plugin->value;
	  arg_set_value(args, "CATEGORY", sizeof(int), (void*)c); /* XXXXXXX */
	  l = l->next;
	  continue;
	 }
#endif	 
	scheduler_mark_running_ports(h, p);
        plugin_set_running_state(p->value, PLUGIN_STATUS_RUNNING);
	return p;
       }
    }
   }
    else /* No dependencies */
     {
        scheduler_mark_running_ports(h, l->plugin);
        plugin_set_running_state(l->plugin->value, PLUGIN_STATUS_RUNNING);
        return l->plugin;
     }
   }
    break;
  case PLUGIN_STATUS_RUNNING:
        {
	int cat = plug_get_category(l->plugin->value);
	if(cat < running_category)
		running_category = cat;
  	flag ++;
	}
	break;

  case PLUGIN_STATUS_DONE :
  	scheduler_rm_running_ports(h, l->plugin);
	plugin_set_running_state(l->plugin->value, PLUGIN_STATUS_DONE_AND_CLEANED);
	/* no break - we remove it right away */
  case PLUGIN_STATUS_DONE_AND_CLEANED:
  	{
	 struct list * old = l->next;

	 if(l->prev != NULL)
	  l->prev->next = l->next;
	 else
	  h->list[category] = l->next;
	  
	 
	 if(l->next != NULL)
	  l->next->prev = l->prev;

	efree(&l);
	l = old;
	
	continue;
	}
	break;
    }
  l = l->next; 
  }
  
  /* Could not find anything */
  if((category == ACT_SCANNER ||
     category == ACT_INIT) && flag != 0)
     {
      pluginlaunch_wait_for_free_process();
      flag = 0;
      category --;
     }
     
   if(category + 1 >= ACT_DENIAL && flag && running_category < ACT_DENIAL)
   	return PLUG_RUNNING;  
 }
 
   return flag == 0 ? NULL : PLUG_RUNNING; 
}


void list_destroy(struct list * list)
{
 while(list != NULL)
 {
  struct list * next = list->next;
  efree(&list);
  list = next;
 }
}


void plugins_scheduler_free(plugins_scheduler_t sched)
{
 int i;
 hash_destroy(sched->hash);
 for(i=ACT_FIRST;i<ACT_LAST;i++)
 	list_destroy(sched->list[i]);	
 efree(&sched);
}
