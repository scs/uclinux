/* Nessus
 * Copyright (C) 1998 - 2002 Renaud Deraison
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
 * Plugins Loader
 *
 */
 
#include <includes.h>

#ifdef NESSUSNT
#include "wstuff.h"
#endif

#include "utils.h"
#include "pluginload.h"
#include "log.h"
#include "preferences.h"
#include "users.h"

static pl_class_t* plugin_classes = NULL;


struct files {
	char * fname;
	struct files * next;
	};
	

#define MAX_FILES 3299


struct files ** files_init()
{
 struct files ** ret;
 int i;
 srand(MAX_FILES);
 ret = emalloc(sizeof(*ret) * (MAX_FILES + 1));
 for(i=0;i<MAX_FILES;i++)
 	ret[i] = NULL;
 return ret;
}

void files_add(struct files ** files, char * fname)
{
 struct files * f;
 int idx;

 f = emalloc(sizeof(*f));
 idx = rand() % MAX_FILES;
 f->fname = estrdup(fname);
 f->next = files[idx];
 files[idx] = f;
}

char * files_walk(struct files ** files, int * idx)
{
 int i = *idx;
 struct files * myfile;
 static char ret[1024];
 
 while(files[i] == NULL)
 {
  i ++;
  if(i >= MAX_FILES)break;
 }
 
 if(files[i] == NULL)
  return NULL;

 *idx = i;
 
 myfile = files[i];
 files[i] = myfile->next;
 strncpy(ret, myfile->fname, sizeof(ret) - 1);
 ret[sizeof(ret) - 1] = '\0';
 

 efree(&myfile->fname);
 efree(&myfile);
 return ret;
}

void files_close(struct files ** files)
{
 int i;
 for(i=0;i<MAX_FILES;i++)
  if(files[i])printf("Warning, forgot some files!!\n");
 
 efree(&files);
 srand(time(NULL));
}





/*
 * main function for loading all the
 * plugins that are in folder <folder>
 */
struct arglist * 
plugins_init(preferences)
 struct arglist * preferences;
{
 return plugins_reload(preferences, emalloc(sizeof(struct arglist)));
}



static struct arglist * 
plugins_reload_from_dir(preferences, plugins, folder)
 struct arglist * preferences;
 struct arglist * plugins;
 char * folder;
{
  DIR * dir;
  struct dirent * dp;
  struct files ** files;
  char * name;
  int idx = 0;
  
  if( plugin_classes == NULL){
   pl_class_t ** cl_pptr = &plugin_classes;
   pl_class_t * cl_ptr;
   int i;
   pl_class_t*  pl_init_classes[] = {
   			&nes_plugin_class,
			&nasl_plugin_class,
#ifdef PERL_PLUGINS
			&perl_plugin_class,
#endif
			NULL 
		};
		
  for (i = 0;  (cl_ptr = pl_init_classes[i]);  ++i) {
	    if ((*cl_ptr->pl_init)(preferences, NULL)) {
	        *cl_pptr = cl_ptr;
		cl_ptr->pl_next = NULL;
		cl_pptr = &cl_ptr->pl_next;
	    }
	}
    }
  
  
  if( folder == NULL)
    {
#ifdef DEBUG
      log_write("%s:%d : folder == NULL\n", __FILE__, __LINE__);
#endif
      print_error("could not determine the value of <plugins_folder>. Check %s\n",
      	(char *)arg_get_value(preferences, "config_file"));
      return plugins;
    }

  if((dir = opendir(folder)) == NULL)
    {
      print_error("Couldn't open the directory called \"%s\" - %s\nCheck %s\n", 
      		   folder,
		   strerror(errno),
      		   (char *)arg_get_value(preferences, "config_file"));
		   
      return plugins;
    }
 
 
  files = files_init();
  while( (dp = readdir(dir)) != NULL )
  {
   if(dp->d_name[0] != '.')
   	files_add(files, dp->d_name);
  }
  
  rewinddir(dir);
  closedir(dir);
  
  /*
   * Add the the plugins
   */
  while((name = files_walk(files, &idx)) != NULL) {
	int len = strlen(name);
	pl_class_t * cl_ptr = plugin_classes;
	

	if(preferences_log_plugins_at_load(preferences))
	 log_write("Loading %s\n", name);
	while(cl_ptr) {
         int elen = strlen(cl_ptr->extension);
	 if((len > elen) && !strcmp(cl_ptr->extension, name+len-elen)) {
	 	struct arglist * pl = (*cl_ptr->pl_add)(folder, name,plugins,
							preferences);
   		if(pl) {
			arg_add_value(pl, "PLUGIN_CLASS", ARG_PTR,
			sizeof(cl_ptr), cl_ptr);
		}
		break;
	}
	cl_ptr = cl_ptr->pl_next;
      }
    }
    
  files_close(files);  

 
  return plugins;
}


struct arglist *
plugins_reload(preferences, plugins)
 struct arglist * preferences;
 struct arglist * plugins;
{
 return plugins_reload_from_dir(preferences, plugins, arg_get_value(preferences, "plugins_folder"));
}

struct arglist *
plugins_reload_user(globals, preferences, plugins)
 struct arglist * globals;
 struct arglist * preferences;
 struct arglist * plugins;
{
 char * home = user_home(globals);
 char * plugdir = emalloc(strlen(home) + strlen("plugins") + 2);
 struct arglist * ret;
 sprintf(plugdir, "%s/plugins", home);
 efree(&home);
 ret = plugins_reload_from_dir(preferences, plugins, plugdir);
 efree(&plugdir);
 return ret;
}

void 
plugin_set_socket(struct arglist * plugin, int soc)
{
 struct arglist * v, *t = plugin;

  v = t->value;
  if(v != NULL)
        {
     	if(arg_get_value(v, "SOCKET") != NULL)
	 arg_set_value(v, "SOCKET", sizeof(int), (void*)soc);
	else
     	 arg_add_value(v, "SOCKET", ARG_INT, sizeof(int), (void *)soc);
	}
}

int
plugin_get_socket(struct arglist * plugin)
{
 struct arglist * v, * t = plugin;
 
 v = t->value;
 if(v != NULL)
 {
  return (int)arg_get_value(v, "SOCKET");
 }
 return -1;
}



void plugin_unlink(plugin)
 struct arglist * plugin;
{
  if(plugin == NULL)
   {
    fprintf(stderr, "Error in plugin_unlink - args == NULL\n");
    return;
   }
  arg_set_value(plugin, "preferences", -1, NULL);
}


void
plugin_free(plugin)
 struct arglist * plugin;
{
 plugin_unlink(plugin);
 arg_free_all(plugin);
}

void
plugins_free(plugins)
 struct arglist * plugins;
{
 struct arglist * p = plugins;
 if(p == NULL)
  return;
 
 while(p->next)
 {
  plugin_unlink(p->value);
  p = p->next;
 }
 arg_free_all(plugins);
}
/*
 * Put our socket somewhere in the plugins
 * arguments
 */
void 
plugins_set_socket(struct arglist * plugins, int soc)
{
  struct arglist * t;

  t = plugins;
  while(t && t->next)
    {
     plugin_set_socket(t, soc);
     t = t->next;
    }
}
