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
 * Plugins requirements
 *
 */ 
 
#include <includes.h>
#include "plugs_req.h"

/**********************************************************
 
 		   Private Functions
	
***********************************************************/
 
extern int kb_get_port_state_proto(struct arglist*, struct arglist*, int, char*);
 
/*---------------------------------------------------------

  Returns whether a port in a port list is closed or not
 
 ----------------------------------------------------------*/
static int
get_closed_ports(keys, ports, preferences)
   struct arglist * keys;
   struct arglist * ports;
   struct arglist * preferences;
{

  if(ports == NULL)
   return -1;
  
  while(ports->next != NULL)
  {
   int iport = atoi(ports->name);			
   if(iport != 0)
   	{
      	if( kb_get_port_state_proto(keys, preferences, iport, "tcp") != 0 )
		return iport;
	}
      else 
        {
      	if( arg_get_value(keys, ports->name) != NULL )
		return 1; /* should be the actual value indeed ! */
	}   
    ports = ports->next;
  }
  return 0; /* found nothing */
}


/*-----------------------------------------------------------

  Returns whether a port in a port list is closed or not
 
 ------------------------------------------------------------*/
static int
get_closed_udp_ports(keys, ports, preferences)
   struct arglist * keys;
   struct arglist * ports;
   struct arglist * preferences;
{   
  if( ports == NULL )
  	return -1;
  else while( ports->next != NULL)
  {
      int iport = atoi(ports->name);				
      if(kb_get_port_state_proto(keys, preferences, iport, "udp"))return iport;
      ports = ports->next;
  }
  return 0; /* found nothing */
}


/*-----------------------------------------------------------
            
	     Returns the name of the first key
	     which is not in <keyring>
	    
 -----------------------------------------------------------*/
static char * 
key_missing(keyring, keys)
  struct arglist * keyring;
  struct arglist * keys;
{
 if(!keyring || !keys)return NULL;
 else {
   while( keys->next != NULL)
   {
     if(arg_get_value(keyring, keys->name) == NULL)
      return keys->name;
     else
      keys = keys->next;
   }
 }
 return NULL;
}

/*-----------------------------------------------------------
            
	    The opposite of the previous function
	    
 -----------------------------------------------------------*/
static char * key_present(keyring, keys)
 struct arglist * keyring;
 struct arglist * keys;
{
 if(!keyring || !keys)return NULL;
 else {
   while( keys->next != NULL)
   {
     if(arg_get_value(keyring, keys->name) != NULL)
      return keys->name;
     else
      keys = keys->next;
   }
 }
 return NULL;
} 

/**********************************************************
 
 		   Public Functions
	
***********************************************************/	




/*------------------------------------------------------

  Returns <port> if the lists of the required ports between
  plugin 1 and plugin 2 have at least one port in common
 
 
 ------------------------------------------------------*/
struct arglist * 
requirements_common_ports(plugin1, plugin2)
 struct arglist * plugin1, *plugin2;
{
 struct arglist * ret = NULL;
 struct arglist * req1, *r1;
 struct arglist * req2, *r2;
 
 
 if(!plugin1 || !plugin2) return 0;
 
 r1 = req1 = plug_get_required_ports(plugin1);
 if(!req1)return 0;
 
 r2 = req2 = plug_get_required_ports(plugin2);
 if(!req2)
 {
  arg_free_all(r1);
  return 0;
 }
 
 while(req1->next != NULL)
 {
  struct arglist * r = req2;
  while(r && r->next)
  {
   if(req1->type == r->type)
   {
      if(r->name && req1->name && !strcmp(r->name, req1->name))
       {
       if(!ret)ret = emalloc(sizeof(struct arglist));
       arg_add_value(ret, r->name, ARG_INT, 0,(void*)1);
       }
   }  
   r = r->next;
  }
  req1 = req1->next;
 }
 arg_free_all(r1);
 arg_free_all(r2);
 return ret;
}


/*-------------------------------------------------------

	Determine if the plugin requirements are
	met.

	Returns NULL is everything is ok, or else
	returns an error message

---------------------------------------------------------*/

char *
requirements_plugin(kb, plugin, preferences)
 struct arglist * kb;
 struct arglist * plugin;
 struct arglist * preferences;
{
  static char error[64];
  char * missing;
  char * present;
  struct arglist * tcp, * udp, * rkeys, * ekeys;
  /*
   * Check wether the good ports are open
   */
  tcp = plug_get_required_ports(plugin->value);
 
  
  if(tcp != NULL && (get_closed_ports(kb, tcp , preferences)) == 0)
     {
      strncpy(error, "none of the required tcp ports are open", sizeof(error) - 1);
      arg_free_all(tcp);
      return error;
     }
   if(tcp != NULL)arg_free_all(tcp);
      
   udp = plug_get_required_udp_ports(plugin->value);  
   if(udp != NULL && (get_closed_udp_ports(kb, udp , preferences)) == 0)
      {
      strncpy(error, "none of the required udp ports are open", sizeof(error) - 1);
      arg_free_all(udp);
      return error;
      }
   if(udp != NULL)arg_free_all(udp);
   
  /*
   * Check wether a key we wanted is missing
   */
  rkeys = plug_get_required_keys(plugin->value);
  if((missing = key_missing(kb, rkeys)))
  {
     snprintf(error,sizeof(error), "because the key %s is missing", missing);
     arg_free_all(rkeys);
     return error;
  }
  if(rkeys != NULL)arg_free_all(rkeys);
  
  /*
   * Check wether a plugin we do not want is present
   */
  ekeys = plug_get_excluded_keys(plugin->value);
  if((present = key_present(kb, ekeys)))
  {
   snprintf(error,sizeof(error), "because the key %s is present", present);
   arg_free_all(ekeys);
   return error;
  }
  if(ekeys != NULL)arg_free_all(ekeys);
  return NULL;
}
