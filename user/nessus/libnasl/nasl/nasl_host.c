/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
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
 * In addition, as a special exception, Renaud Deraison and Michel Arboi
 * give permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 */
 /*
  * This file contains all the functions which deal with the remote host :
  * which ports are open, what is its IP, what is our IP, what transport
  * is on the remote port, and so on...
  */
  
#include <includes.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"  

#include "nasl_host.h"

tree_cell * get_hostname(lex_ctxt * lexic)
{
 struct arglist *  script_infos = lexic->script_infos;
 char * hostname = (char*)plug_get_host_fqdn(script_infos);
 tree_cell * retc;

 if( hostname == NULL )
	 return NULL;

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_STR;
 retc->size = strlen(hostname);
 retc->x.str_val = estrdup(hostname);
 return retc;
}

tree_cell * get_host_ip(lex_ctxt * lexic)
{
 struct arglist *  script_infos = lexic->script_infos;
 struct in_addr * ip = plug_get_host_ip(script_infos);
 char * txt_ip;
 tree_cell * retc;

 if(ip == NULL) /* WTF ? */
 {
   return FAKE_CELL;
 }

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_STR;
 txt_ip = inet_ntoa(*ip);
 retc->x.str_val = estrdup(txt_ip);
 retc->size = strlen(retc->x.str_val);

 return retc;
}

tree_cell * get_host_open_port(lex_ctxt * lexic)
{
 struct arglist *  script_infos = lexic->script_infos;
 unsigned int port = plug_get_host_open_port(script_infos);
 tree_cell * retc;

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_INT;
 retc->x.i_val = port;

 return retc;
}

tree_cell * get_port_state(lex_ctxt * lexic)
{
 int open;
 struct arglist *  script_infos = lexic->script_infos;
 tree_cell * retc;
 int port;

 port = get_int_var_by_num(lexic, 0, -1);
 if(port < 0)
	 return FAKE_CELL;

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_INT;
 open = host_get_port_state(script_infos, port);
 retc->x.i_val = open;
 return retc;
}


tree_cell * get_udp_port_state(lex_ctxt * lexic)
{
 int open;
 struct arglist *  script_infos = lexic->script_infos;
 tree_cell * retc;
 int port;

 port = get_int_var_by_num(lexic, 0, -1);
 if(port < 0)
	 return FAKE_CELL;

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_INT;
 open = host_get_port_state_udp(script_infos, port);
 retc->x.i_val = open;
 return retc;
}


tree_cell * nasl_islocalhost(lex_ctxt * lexic)
{
  struct arglist * script_infos = lexic->script_infos;
  struct in_addr * dst = plug_get_host_ip(script_infos);
  tree_cell * retc;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val =  islocalhost(dst);
  return retc;
}


tree_cell * nasl_islocalnet(lex_ctxt * lexic)
{
 struct arglist *  script_infos = lexic->script_infos;
 struct in_addr * ip = plug_get_host_ip(script_infos);
 tree_cell * retc;
 
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_INT;
 retc->x.i_val = is_local_ip(*ip);
 return retc;
}


tree_cell * nasl_this_host(lex_ctxt * lexic)
{
 struct arglist * script_infos = lexic->script_infos;
 char * ip = NULL;
 tree_cell * retc;
 
 struct in_addr addr;
 
 
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 
 addr = socket_get_next_source_addr(arg_get_value(script_infos, "globals"));
 if ( addr.s_addr != INADDR_ANY )
 {
  retc->x.str_val = estrdup(inet_ntoa(addr));
  retc->size = strlen(retc->x.str_val);
  return retc;
 }
 
 if((ip = plug_get_key(script_infos, "localhost/ip")) != NULL)
 {
  retc->x.str_val = estrdup(ip);
  retc->size = strlen(ip);
 }
 else
 {
 char hostname[255];
 char * ret;
 struct in_addr addr;
 struct in_addr *  ia = plug_get_host_ip(script_infos);
 struct in_addr src;
 src.s_addr = 0;
 if(ia)
 {
 if(islocalhost(ia))
  src.s_addr = ia->s_addr;
 else routethrough(ia, &src);
 
 if(src.s_addr){
   char * ret;
   
   ret = estrdup(inet_ntoa(src));
   retc->x.str_val = ret;
   retc->size = strlen(ret);
   
   return retc;
   }
 }
  
  hostname[sizeof(hostname) - 1] = '\0';
  gethostname(hostname, sizeof(hostname) - 1);
  addr = nn_resolve(hostname);
 
  ret = estrdup(inet_ntoa(addr));
  retc->x.str_val = ret;
  retc->size = strlen(ret);
 }
 return retc;
}

tree_cell * nasl_this_host_name(lex_ctxt * lexic)
{
 char * hostname;
 tree_cell * retc;
 
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 
 hostname = emalloc(256);
 gethostname(hostname, 255);
 
 retc->x.str_val = hostname;
 retc->size = strlen(hostname);
 return retc;
}


tree_cell * get_port_transport(lex_ctxt * lexic)
{
 struct arglist * script_infos =  lexic->script_infos;
 tree_cell *retc;
 int port = get_int_var_by_num(lexic, 0, -1);

 if(port >= 0)
 {
   int trp = plug_get_port_transport(script_infos, port);
   retc = alloc_tree_cell(0, NULL);
   retc->type = CONST_INT;
   retc->x.i_val = trp;
   return retc;
 }
 return NULL;
}
