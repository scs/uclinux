/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 * Plugins Inter Communication
 * -   -   -     -
 *
 * This set of functions just read what the plugin writes on its pipe,
 * and put it in an arglist
 */ 
 
#include <includes.h>
#include "log.h"
#include "save_kb.h"
#include "utils.h"
#include "piic.h"




void 
piic_parse(globals, args, pip, buf)
 struct arglist * globals, *args;
 int pip;
 char * buf;
{
 char * t;
 int type;
 char *c;
 
 
 if(!buf)
  return;
  
 if(buf[strlen(buf)-1]=='\n')
 	buf[strlen(buf)-1]='\0';
	
 c = strrchr(buf, ';');
 if(c)c[0] = 0;
 t = strchr(buf, ' ');
 if(!t)return;
 t[0] = '\0';
 type = atoi(buf);
 t[0] = ' ';
 if(type != ARG_ARGLIST){
  char * value = strchr(buf, '=');
  char * copy;
  char * name;
  struct arglist * arg = NULL;
  int this_type;
  
  if(!value)return;
  value[0]=0;
  value++;
  
  name = t+1;
  
  if(!args)
  	{
	log_write("piic_parse() : error - args == NULL\n");
  	return;
	}
	
	
  if((this_type = arg_get_type(args, name))==ARG_ARGLIST)
  {
   arg = arg_get_value(args, name);
  }
  else
  {
   if(this_type > 0)
   {
    
    /*
     * Let's just check that we are not adding twice the same
     * value
     */
    if(this_type == ARG_STRING)
    {
     char * t = arg_get_value(args, name);
     if(t){
     if(!strcmp(t, value))
      return;
      }
     }
     else if(this_type == ARG_INT)
     {
      int tt = (int)t;
      if(tt == atoi(value))
       return;
     }
    arg = emalloc(sizeof(struct arglist));
    arg_add_value(arg, name, this_type, -1, arg_get_value(args, name));
    arg_set_value(args, name, -1, arg);
    arg_set_type(args, name, ARG_ARGLIST);
   }
   else arg = args;
  }
  if(type==ARG_STRING)
   {
   copy = rmslashes(value);
   arg_add_value(arg,name, ARG_STRING, strlen(copy), copy);
   if(save_kb(globals))
    save_kb_write_str(globals, arg_get_value(globals, "CURRENTLY_TESTED_HOST"), name, copy);
   }
  else if(type==ARG_INT)
   {
   arg_add_value(arg, name, ARG_INT, sizeof(int), (void *)atoi(value)); 
   if(save_kb(globals))
    save_kb_write_int(globals, arg_get_value(globals, "CURRENTLY_TESTED_HOST"), name, atoi(value));      
   }
  }
}


/*
 * If a thread sends something through
 * its communication socket, we read it here.
 *
 * We could make things go even faster if
 * tv.tv_usec was set to 0, but this way
 * (equals to 3000) we have a nice balance
 * between CPU usage and overall speed
 */ 
int 
piic_read_socket(globals, args, soc)
 struct arglist * globals, *args;
 int soc;
{
 char buf[65536];
 fd_set rd;
 int e;
 struct timeval tv;
 int ret = 0;
 
 
 
again: 
 tv.tv_sec = 0;
 tv.tv_usec = 3000;
 FD_ZERO(&rd);
 FD_SET(soc, &rd);
 e = select(soc+1, &rd, NULL, NULL, &tv);
 if (e < 0 && errno == EINTR) goto again;
 if( e > 0 )
 {
  while(data_left(soc) > 0)
  {
  int n;
  bzero(buf, sizeof(buf));
  n = recv_line(soc, buf, sizeof(buf) - 1);
  if(n <= 0)
   return ret;
  piic_parse(globals, args, soc, buf);
  ret ++;
  }
 }
 return ret;
}


