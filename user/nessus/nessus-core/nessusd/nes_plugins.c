/* Nessus
 * Copyright (C) 1999 - 2003 Renaud Deraison
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
 * Old style nessus plugins, implemented as shared libraries.
 *
 */

#include <includes.h>
#include "pluginload.h"
#include "plugs_hash.h"
#include "processes.h"
#include "log.h"
#include "preferences.h"

static int nes_thread(struct arglist *);

#ifdef HAVE_SHL_LOAD	/* this is HP/UX */
ext_library_t dlopen(name)
 char* name;
{
 return (ext_library_t)shl_load(name, BIND_IMMEDIATE|BIND_VERBOSE|BIND_NOSTART, 0L);
}

void * 
dlsym(lib, name)
 shl_t lib;
 char * name;
{
 void* ret;
 int status;
 status = shl_findsym((shl_t *)&lib, name, TYPE_PROCEDURE, &ret);
 if((status == -1) && (errno == 0))
 {
  status = shl_findsym((shl_t *)&lib, name, TYPE_DATA, &ret);
 }
 
 return (status == -1 ) ? NULL : ret;
}

void
dlclose(x)
 shl_t * x;
{
 shl_unload(x);
}

char*
dlerror()
{
 return strerror(errno);
}

#else /* HAVE_SHL_LOAD */
#ifdef HAVE_NSCREATEOBJECTFILEIMAGEFROMFILE /* Darwin */
#if defined(HAVE_DL_LIB) || defined(HAVE_DLFNC_H)
#define dlopen macosx_dlopen
#define dlsym macosx_dlsym
#define dlclose macosx_dlclose
#define dlerror macosx_dlerror
#undef HAVE_DL_LIB
#endif
#include <mach-o/dyld.h>

ext_library_t
dlopen(name)
 char* name;
{
 NSObjectFileImage ofile;
 
 if(NSCreateObjectFileImageFromFile(name, &ofile) != NSObjectFileImageSuccess)
 {
  fprintf(stderr, "NSCreateObjectFileImageFromFile(%s) failed\n", name);
  return NULL;
 }

 return NSLinkModule(ofile, name, NSLINKMODULE_OPTION_PRIVATE|
				  NSLINKMODULE_OPTION_BINDNOW);
}

void * 
dlsym(lib, name)
 void* lib;
 char * name;
{
 NSSymbol nsSymbol = NSLookupSymbolInModule((NSModule)lib, name); 
 if(nsSymbol == NULL)
 {
  /* fprintf(stderr, "NSLookupSymbolInModule(%x, %s) failed\n", lib, name); */
  return NULL;
 }
 return NSAddressOfSymbol(nsSymbol);
}

void
dlclose(x)
 void * x;
{
 NSUnLinkModule((NSModule)(x), NSUNLINKMODULE_OPTION_NONE);
}

char*
dlerror()
{
 return strerror(errno);
}
#endif /* Darwin */
#endif

/*
 *  Initialize this class
 */
pl_class_t* nes_plugin_init(struct arglist* prefs, struct arglist* args) {
    return &nes_plugin_class;
}

/*
 * add *one* .nes (shared lib) plugin to the server list
 */
struct arglist * 
nes_plugin_add(folder, name, plugins, preferences)
     char * folder;
     char * name;
     struct arglist * plugins;
     struct arglist * preferences;
{
 ext_library_t ptr = NULL; 
 char fullname[PATH_MAX+1];
 struct arglist * prev_plugin = NULL;
 struct arglist * args = NULL;
 char * md5;
 
 
 snprintf(fullname, sizeof(fullname), "%s/%s", folder, name);
 
 md5 = file_hash(fullname);
  
 
 args = store_load_plugin(folder, name, md5, preferences);
 if( args == NULL )
 {
  if((ptr = LOAD_LIBRARY(fullname))== NULL){
    log_write("Couldn't load %s - %s\n", name, LIB_LAST_ERROR());
  }
  else {
    plugin_init_t  f_init;
   
    if((f_init = (plugin_init_t)LOAD_FUNCTION(ptr, "plugin_init")) ||
    	(f_init = (plugin_init_t)LOAD_FUNCTION(ptr, "_plugin_init")))
      {
	int e;
      	args = emalloc(sizeof(struct arglist));
      	arg_add_value(args, "preferences", ARG_ARGLIST, -1, (void*)preferences);
      	e = (*f_init)(args);
	if(e >= 0)
	{  
	 plug_set_path(args, fullname);
	 args =  store_plugin(args, name, md5); 
	}
	else
	{
	 arg_set_value(args, "preferences", -1, NULL);
	 arg_free_all(args);
	 args = NULL;
	}
      }
    else log_write("Couldn't find the entry point in %s [%s]\n", name,LIB_LAST_ERROR());
    CLOSE_LIBRARY(ptr);
   }
  }
  
  if( args != NULL )
  {
   prev_plugin = arg_get_value(plugins, name);
   plug_set_launch(args, 0);
   if( prev_plugin == NULL )
          arg_add_value(plugins, name, ARG_ARGLIST, -1, args);
    else
         {
          plugin_free(prev_plugin);
          arg_set_value(plugins, name, -1, args);
         }
  }
   efree(&md5);
   return args;
}


int
nes_plugin_launch(globals, plugin, hostinfos, preferences, kb, name, soc)
	struct arglist * globals;
	struct arglist * plugin;
	struct arglist * hostinfos;
	struct arglist * preferences;
	struct arglist * kb; /* knowledge base */
	char * name;
	int soc;
{
 nthread_t module;
 plugin_run_t func = NULL;
 ext_library_t ptr = NULL;

 
 
 ptr = LOAD_LIBRARY(name);
 if( ptr == NULL)
 	return -1;
	
	
 func = (plugin_run_t)LOAD_FUNCTION(ptr, "plugin_run");
 if( func == NULL)
 	func = (plugin_run_t)LOAD_FUNCTION(ptr, "_plugin_run");
	
 if( func == NULL )
 	{
 	log_write("no 'plugin_run()' function in %s\n", name);
	return -1;
	}


 arg_add_value(plugin, "globals", ARG_ARGLIST, -1, globals);
 arg_add_value(plugin, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);
 arg_add_value(plugin, "func", ARG_PTR, -1, func);
 arg_add_value(plugin, "name", ARG_STRING, strlen(name), name);
 arg_set_value(plugin, "preferences", -1, preferences);
 arg_add_value(plugin, "pipe", ARG_INT, sizeof(int), (void*)soc);
 arg_add_value(plugin, "key", ARG_ARGLIST, -1, kb);
 module = create_process((process_func_t)nes_thread, plugin);
 CLOSE_LIBRARY(ptr);
 return module;
}

static int nes_thread(args)
 struct arglist * args;
{
 int soc = (int)arg_get_value(args, "pipe");
 int soc2 = (int)arg_get_value(args, "SOCKET");
 struct arglist * globals = arg_get_value(args, "globals");
 int i;
 plugin_run_t func;

 if(preferences_benice(NULL))nice(-5);


 /* XXX ugly hack */
 arg_set_value(globals, "global_socket", sizeof(int), (void*)soc2);
 for(i=4;i<256;i++)
 {
  if( ( i != soc )  && (i != soc2 ) )
    close(i);
 }
 
 #ifdef RLIMIT_RSS
 {
 struct rlimit rlim;
 getrlimit(RLIMIT_RSS, &rlim);
 rlim.rlim_cur = 1024*1024*40;
 rlim.rlim_max = 1024*1024*40;
 setrlimit(RLIMIT_RSS, &rlim);
 }
#endif

#ifdef RLIMIT_AS
 {
 struct rlimit rlim;
 getrlimit(RLIMIT_AS, &rlim);
 rlim.rlim_cur = 1024*1024*40;
 rlim.rlim_max = 1024*1024*40;
 setrlimit(RLIMIT_AS, &rlim);
 }
#endif

#ifdef RLIMIT_DATA
 {
 struct rlimit rlim;
 getrlimit(RLIMIT_DATA, &rlim);
 rlim.rlim_cur = 1024*1024*40;
 rlim.rlim_max = 1024*1024*40;
 setrlimit(RLIMIT_DATA, &rlim);
 }
#endif


 setproctitle("testing %s (%s)", (char*)arg_get_value(arg_get_value(args, "HOSTNAME"), "NAME"), (char*)arg_get_value(args, "name"));
 func = arg_get_value(args, "func");
 signal(SIGTERM, _exit);
 return func(args);
}

pl_class_t nes_plugin_class = {
    NULL,
    ".nes",
    nes_plugin_init,
    nes_plugin_add,
    nes_plugin_launch,
};
