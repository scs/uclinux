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
#include <includes.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_debug.h"
#include "nasl_socket.h"

#include "nasl_http.h"

/*-----------------[ http_* functions ]-------------------------------*/
 


  
 

tree_cell * http_open_socket(lex_ctxt * lexic)
{
 return nasl_open_sock_tcp(lexic);
}

tree_cell * http_close_socket(lex_ctxt * lexic)
{ 
 return nasl_close_socket(lexic);
}


static tree_cell * _http_req(lex_ctxt* lexic, char* keyword)
{
 tree_cell * retc;
 char * str;
 char * item = get_str_local_var_by_name(lexic, "item");
 char * data = get_str_local_var_by_name(lexic, "data");
 int    port = get_int_local_var_by_name(lexic, "port", -1);
 char *ver, *url = NULL;
 struct arglist * script_infos = lexic->script_infos;
 char *auth, tmp[32];
 int	cl;
 int    al;
 char	content_l_str[32];


 if( item == NULL || port < 0)
 {
  nasl_perror(lexic, "Error : http_* functions have the following syntax :\n");
  nasl_perror(lexic, "http_*(port:<port>, item:<item> [, data:<data>]\n" );
  return NULL;
 } 
 
 if (port <= 0 || port > 65535)
 {
   nasl_perror(lexic, "http_req: invalid value %d for port parameter\n", port);
   return NULL;
 }

 snprintf(tmp, sizeof(tmp), "/tmp/http/auth/%d", port);
 auth = plug_get_key(script_infos, tmp);

 if (auth == NULL)
   auth = plug_get_key(script_infos, "http/auth");

 snprintf(tmp, sizeof(tmp), "http/%d", port);
 ver = plug_get_key(script_infos, tmp);

 if (data == NULL)
   {
     cl = 0; *content_l_str = '\0';
   }
 else
   {
     cl = strlen(data);
     snprintf(content_l_str, sizeof(content_l_str), "Content-Length: %d\r\n", cl);
   }

 if(auth)
    al = strlen(auth);
 else
    al = 0;
    
 if((ver == NULL) || strcmp(ver, "11") == 0)
 {
  char	*hostname, *ua;
 
  hostname = (char*)plug_get_host_fqdn(script_infos);
  if( hostname == NULL ) return NULL;
  ua = plug_get_key(script_infos, "http/user-agent");
 #define NESSUS_USER_AGENT	"Mozilla/4.75 [en] (X11, U; Nessus)"
  if (ua == NULL)
    ua = NESSUS_USER_AGENT;
  else
    {
      while (isspace(*ua))
	ua ++;
      if (*ua == '\0')
	ua = NESSUS_USER_AGENT;
    }

  url = build_encode_URL(script_infos, keyword, NULL, item, "HTTP/1.1");
  str = emalloc(strlen(url) + strlen(hostname) + al + cl + strlen(ua) + 1024);
  /* NIDS evasion */
  sprintf(str, "%s\r\n\
Connection: Close\r\n\
Host: %s\r\n\
Pragma: no-cache\r\n\
User-Agent: %s\r\n\
Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n\
Accept-Language: en\r\n\
Accept-Charset: iso-8859-1,*,utf-8\r\n",
		url, hostname, ua);
 }
 else
 {
   /* NIDS evasion */
   url = build_encode_URL(script_infos, keyword, NULL, item, "HTTP/1.0\r\n");

 str = emalloc(strlen(url) + al + cl + 120);
 strcpy(str, url);
 }
 efree(&url);

 if (auth != NULL)
   {
     strcat(str, auth);
     strcat(str, "\r\n");
   }

 if (data != NULL)
   strcat(str, content_l_str);
 
 strcat(str, "\r\n");

 if (data != NULL)
   {
     strcat(str, data);
   }

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = strlen(str);
 retc->x.str_val = str;
 return retc;
}
/*
 * Syntax :
 *
 * http_get(port:<port>, item:<item>);
 *
 */
tree_cell * http_get(lex_ctxt * lexic)
{
 return _http_req(lexic, "GET");
}

/*
 * Syntax :
 *
 * http_head(port:<port>, item:<item>);
 *
 */
tree_cell * http_head(lex_ctxt * lexic)
{
 return _http_req(lexic, "HEAD");
}


/*
 * Syntax :
 * http_post(port:<port>, item:<item>)
 */
tree_cell * http_post(lex_ctxt * lexic)
{
 return _http_req(lexic, "POST");
}

/*
 * http_delete(port:<port>, item:<item>)
 */
tree_cell * http_delete(lex_ctxt * lexic)
{
  return _http_req(lexic, "DELETE");
}

/*
 * http_put(port:<port>, item:<item>, data:<data>)
 */
tree_cell * http_put(lex_ctxt * lexic)
{
  return _http_req(lexic, "PUT");
}


/*
 * Syntax :
 * http_recv_header(soc)
 */
tree_cell * http_recv_headers(lex_ctxt * lexic)
{
 tree_cell * retc;
 int soc = get_int_var_by_num(lexic, 0, -1);
 char * buf;
 int sz = 8192;
 int num = 0;
 char tmp[2048];
 int n;
 int lines = 0;

 if(soc <= 0)
 {
  nasl_perror(lexic, "http_recv_header(): syntax: http_recv_header(<soc>)\n");
  return NULL;
 }
 
 buf = emalloc(sz);
 
  for(;;)
  {
   n = recv_line(soc, tmp, sizeof(tmp) - 1);
   lines ++;
   if(n <= 0)break;
   if(!strcmp(tmp, "\r\n")||
      !strcmp(tmp, "\n"))break;
   else 
   {
     num  += n;
     if(num < sz)
      strcat(buf, tmp);
     else
     {
      if(sz > 1024 * 1024)
       break;
      else
       sz = sz * 2;
	
	 
      buf = erealloc(buf, sz);
      strcat(buf, tmp);
      if(lines > 100)break;
     }
  }
 }

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = num;
 retc->x.str_val = buf;
 return retc;
}

/*-------------------[ cgibin() ]--------------------------------*/

/*
 * XXXXX process management
 */ 
static int _cgibin_son;

static void 
cgibin_sighand_term(int sig)
{
 if(_cgibin_son)
 {
  kill(_cgibin_son, SIGTERM);
  _cgibin_son = 0;
 }
 _exit(0);
}

static void
sig_n(n, f)
 int n;
 void * f;
{
 #ifdef HAVE_SIGACTION
  struct sigaction sa;
  sa.sa_handler = f;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(n,&sa,(struct sigaction *) 0);
#else
  signal(n, f);
#endif
}

static void
sig_term(f)
 void *f;
{
 sig_n(SIGTERM, f);
}

static void
sig_alarm(f)
 void * f;
{
 sig_n(SIGALRM, f);
}
 
tree_cell *cgibin(lex_ctxt * lexic)
{
 struct arglist * script_infos = lexic->script_infos;
 struct arglist * prefs = arg_get_value(script_infos, "preferences");
 char * path = prefs == NULL ? NULL : arg_get_value(prefs, "cgi_path");
 char * t;
 char * orig;
 pid_t pid;
 tree_cell * retc;

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 
 if(path == NULL)
	 	path = "/cgi-bin:/scripts";

 path = orig = estrdup(path);
 while((t = strchr(path, ':')) != NULL)
  { 
   /*
    * XXX fixme : handle the child's timeout
    */
   if(!(pid = fork()))
   {
   /* so that we don't fork() later on... */
   arg_set_value(prefs, "cgi_path", strlen(path), path);
   sig_term(_exit);
   sig_alarm(_exit);
   alarm(120);
   t[0]='\0';
   retc->x.str_val = estrdup(path);
   retc->size = strlen(path);
   efree(&orig);
   return retc;
   }
   else
   {
    if(pid < 0)
    {
     nasl_perror(lexic, "libnasl:cgibin(): fork() failed (%s)\n", strerror(errno));
     return NULL;
    }
    else
    {
    _cgibin_son = pid;
    sig_term(cgibin_sighand_term);
    waitpid(pid, NULL, 0);
    _cgibin_son = 0;
    sig_term(exit);
    }
   }
    
   path = t + 1; 
  }
  
  retc->x.str_val = estrdup(path);
  retc->size = strlen(path);
  efree(&orig);
    
    
  return retc;
}



/*-------------------------------------------------------------------------*/

tree_cell * nasl_is_cgi_installed(lex_ctxt * lexic)
{
 char * cgi = get_str_local_var_by_name(lexic, "item");
 int port = get_int_local_var_by_name(lexic, "port", -1);
 struct arglist *  script_infos = lexic->script_infos;
 tree_cell * retc;

 if (cgi != NULL )
 {
  if(port != 0) 
   port = is_cgi_installed_by_port(script_infos, cgi, port);
   else 
   port = is_cgi_installed(script_infos, cgi);
 }
 else
 {
  cgi = get_str_var_by_num(lexic, 0);
  if(cgi != NULL)
   {
    port = is_cgi_installed(script_infos, cgi);
   }
 }

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_INT;
 retc->x.i_val = port;

 return retc;
}
