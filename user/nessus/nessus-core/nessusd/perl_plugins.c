/* Nessus
 * Copyright (C) 1999-2001 Renaud Deraison
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
 * Perl Plugins, based on Net::Nessus::Plugin from Jochen Wiedmann
 *
 */
 
#include <includes.h>

#ifdef PERL_PLUGINS

#include "pluginload.h"

#include <EXTERN.h>
#include <perl.h>


/*
 *  Initialize the Perl interpreter
 */
static PerlInterpreter* my_perl = NULL;
static pl_class_t* perl_plugin_init(struct arglist* prefs) {
    if (!my_perl) {
        char* args[] = { "nessusd", NESSUSD_INIT_PL, NULL };
	char* path = arg_get_value(prefs, "perl_init_pl");
	if (path) {
	    log_write("Initializing Perl Plugins from Prefs path %s\n",
		      path);
	    args[1] = path;
	} else {
	    log_write("Initializing Perl Plugins from default path %s\n",
		      args[1]);
	}
        my_perl = perl_alloc();
	perl_construct(my_perl);
	perl_parse(my_perl, NULL, 2, args, NULL);
	perl_run(my_perl);
    }
    return &perl_plugin_class;
}


/*
 *  Add *one* .pl plugin to the plugin list
 */
static struct arglist* perl_plugin_add(char* folder, char* name,
				       struct arglist* plugins_all,
				       struct arglist* preferences) {
    struct arglist* plugins = arg_get_value(plugins_all, "plugins");
    struct arglist* plugin = NULL;
    SV* my_class = perl_get_sv("Net::Nessus::Plugins::plugins_class",
			       FALSE);
    char * lang = "english";
    int count;
    SV* plugin_sv = NULL;
    dSP;
    ENTER;
    SAVETMPS;

    if (!my_class) {
        croak("plugins_class not initialized");
    }

    PUSHMARK(SP);
    XPUSHs(my_class);
    XPUSHs(sv_2mortal(newSVpv("folder", 6)));
    XPUSHs(sv_2mortal(newSVpv(folder, strlen(folder))));
    XPUSHs(sv_2mortal(newSVpv("name", 4)));
    XPUSHs(sv_2mortal(newSVpv(name, strlen(name))));
    if (arg_get_type(preferences, "language") >= 0) {
        lang = arg_get_value(preferences, "language");
	if (lang  &&  strlen(lang)) {
	    XPUSHs(sv_2mortal(newSVpv("language", 8)));
	    XPUSHs(sv_2mortal(newSVpv(lang, strlen(lang))));
	}
    }
    PUTBACK;
    count = perl_call_method("add", G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count) {
        plugin_sv = POPs;
    }
    PUTBACK;

    if (plugin_sv  &&  SvTRUE(plugin_sv)) {
        SV* category_sv;
        PUSHMARK(SP);
        XPUSHs(plugin_sv);
	PUTBACK;
	count = perl_call_method("Category", G_SCALAR);
	SPAGAIN;
	if (count) {
	    struct arglist* pl = arg_get_value(plugins_all, 
					       (POPi == ACT_SCANNER) ?
					       "scanners" : "plugins");
	    plugin = emalloc(sizeof(struct arglist));
	    arg_add_value(plugin, "SV", ARG_PTR, sizeof(plugin_sv), plugin_sv);
	    arg_add_value(pl, name, ARG_ARGLIST, -1, (void*) plugin);
	}
    }
    FREETMPS;
    LEAVE;
    return plugin;
}


/*
 *  Launch *one* perl plugin.
 */
static void perl_plugin_launch(struct arglist * globals,
			       struct arglist * plugin,
			       struct arglist * hostinfos,
			       struct arglist * preferences,
			       struct arglist * kb,
			       struct arglist * name) {
    struct arglist * args = arg_get_value(plugin, "plugin_args");
    int timeout = (int) arg_get_value(args, "TIMEOUT");
    int category = (int) arg_get_value(args, "CATEGORY");
    SV* plugin_sv = arg_get_value(plugin, "SV");
    dSP;

    if (!plugin_sv) {
        log_write("perl_launch_script: Missing SV in Perl plugin %s\n",
		  name || "(Unknown name)"));
	return;
    }

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(plugin_sv);
    XPUSHs((category == ACT_SCANNER) ? &PL_sv_undef :
	   sv_2mortal(newSViv(timeout || PLUGIN_TIMEOUT)));
    PUTBACK;
    perl_call_method("Launch", G_DISCARD | G_EVAL);
    FREETMPS;
    LEAVE;
}


pl_class_t perl_plugin_class = {
    NULL,
    ".npl",
    perl_plugin_init,
    perl_plugin_add,
    perl_plugin_launch,
};

#endif /* PERL_PLUGINS */
