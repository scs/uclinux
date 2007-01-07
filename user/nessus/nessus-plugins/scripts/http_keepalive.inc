# -*- Fundamental -*-
# http_keepalive.inc
# (C) Renaud Deraison
# $Id: http_keepalive.inc,v 1.26 2003/10/08 15:22:20 renaud Exp $
#
#
# The only function which should be used by an external plugin is
# http_keepalive_send_recv(port, data) which returns the result
# (or NULL if no connection could be established).
#
# Note that the file "http_func.inc" must also be included when
# using this file.
#


__ka_socket = 0;
__ka_port   = 0;
__ka_enabled = -1;
__ka_last_request = "";



#
# Based on the last headers we received, we determine if we need
# to close our socket and re-open it or not
#
function http_keepalive_check_connection(headers)
{
 tmp = egrep(pattern:"^Connection: [Cc]lose", string:headers);
 if(tmp)
 {
     http_close_socket(__ka_socket);
     __ka_socket = http_open_socket(__ka_port);
 }
}

function enable_keepalive(port)
{
 __ka_enabled = 1;
 __ka_port    = port;
 __ka_socket  = http_open_socket(port);
}
#
# This function determines if the remote web server is
# keep-alive-enabled or not.
#
function http_keepalive_enabled(port)
{
  local_var req, soc, r, kb;
  
  kb = get_kb_item(string("www/", port, "/keepalive"));

  if(kb == "yes"){
  	enable_keepalive(port:port);
	return(1);
	}
  else if(kb == "no")return(0);

  req = string("GET / HTTP/1.1\r\n",
"Connection: Keep-Alive\r\n",
"Host: ", get_host_name(), "\r\n",
"Pragma: no-cache\r\n",
"User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n\r\n");

  soc = http_open_socket(port);
  if(!soc)return NULL;
  send(socket:soc, data:req);
  r = http_recv(socket:soc);


  # Apache
  if(egrep(pattern:"^Keep-Alive:.*", string:r))
  	{
	http_close_socket(soc);
	set_kb_item(name:string("www/", port, "/keepalive"), value:"yes");
	enable_keepalive(port:port);
    	return(1);
	}
  else
  	{
	# IIS
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	if(strlen(r)){
		set_kb_item(name:string("www/", port, "/keepalive"), value:"yes");
		enable_keepalive(port:port);
		return(1);
		}
	}

 set_kb_item(name:string("www/", port, "/keepalive"), value:"no");
 return(0);
}


#
# This function is akin to http_recv() except that if the last request
# was a HEAD, we bail out (whereas http_recv() will timeout).
#
function http_keepalive_recv(bodyonly)
{
  local_var headers, body, length, tmp, chunked, killme;

  killme = 0;
  length = -1;
  headers = http_recv_headers(__ka_socket);
  if(strlen(headers) == 0)headers = http_recv_headers(__ka_socket);

  if(ereg(pattern:"^HEAD.*HTTP/.*", string:__ka_last_request))
   {
   # HEAD does not return a body
   http_keepalive_check_connection(headers:headers);
   if(bodyonly) return("");
   else return(headers);
   }


  if("Content-Length" >< headers)
  {
    tmp = egrep(string:headers, pattern:"^Content-Length: *[0-9]*");
    length = int(ereg_replace(string:tmp, pattern:"^Content-Length: *([0-9]*)", replace:"\1"));
  }



 if((length < 0) && (egrep(pattern:"transfer-encoding: chunked", string:headers, icase:TRUE)))
 {
   while(1)
   {
   tmp = recv_line(socket:__ka_socket, length:4096);
   length = hex2dec(xvalue:tmp);
   if(length > 1024*1024*10)
   	{
   	length = 1024*1024;
	killme = 1;
	}
   body  = string(body, recv(socket:__ka_socket, length:length+2, min:length+2));
   if(strlen(body) > 1024*1024*10)killme = 1;

   if(length == 0 || killme){
   	http_keepalive_check_connection(headers:headers);
    # This is expected - don't put this line before the previous
   	if(bodyonly) return(body);
    else return(string(headers,"\r\n", body));
	}
   }
 }


 if(length >= 0)
 {
   # Don't receive more than 10MB
   if(length > 1024*1024*10)length = 1024*1024;

   body = recv(socket:__ka_socket, length:length, min:length);
 }
 else {
 	# If we don't have the length, we close the connection to make sure
	# the next request won't mix up the replies.

 	#display("ERROR - Keep Alive, but no length!!!\n", __ka_last_request);
	body = recv(socket:__ka_socket, length:16384);
	http_close_socket(__ka_socket);
	__ka_socket = http_open_socket(__ka_port);
	}


 http_keepalive_check_connection(headers:headers);
 if(bodyonly) return(body);
 else return(string(headers,"\r\n", body));
}


#----------------------------------------------------------------------#

# We close our socket on exit.
function on_exit()
{
  if(__ka_socket)
  {
    http_close_socket(__ka_socket);
  }
}



#----------------------------------------------------------------------#


#
# This is our "public" Keep-Alive function. It sends <data> to the remote
# host on port <port>, and returns the result, or NULL if no connection
# could be established.
#
function http_keepalive_send_recv(port, data, bodyonly)
{
  local_var id, n, ret;
  
  #if("Authorization" >!< data && get_kb_item("www/" + port + "/password_protected"))return NULL;
  if(__ka_enabled == -1)__ka_enabled = http_keepalive_enabled(port:port);



  if(__ka_enabled == 0)
  {
    local_var soc, r;
    soc = http_open_socket(port);
    if(!soc)return NULL;
    send(socket:soc, data:data);
    headers = http_recv_headers(soc);
    if(headers) body = http_recv_body(socket:soc, headers:headers, length:0);
    http_close_socket(soc);
    if(bodyonly) return(body);
    else return(string(headers, "\r\n", body));
  }
  



  if((port != __ka_port)||(!__ka_socket))
  {
    if(__ka_socket)http_close_socket(__ka_socket);
    __ka_port = port;
    __ka_socket = http_open_socket(port);
    if(!__ka_socket)return NULL;
  }

  id = stridx(data, string("\r\n\r\n"));
  data = str_replace(string:data, find:"Connection: Close", replace:"Connection: Keep-Alive", count:1);
  __ka_last_request = data;
  n = send(socket:__ka_socket, data:data);
  if(n <= 0)
  {
    http_close_socket(__ka_socket);
    __ka_socket = http_open_socket(__ka_port);
    if(__ka_socket == 0)return NULL;
    send(socket:__ka_socket, data:data);
  }

  return(http_keepalive_recv(bodyonly:bodyonly));
}



#
# Same as check_win_dir_trav(), but with KA support
#
function check_win_dir_trav_ka(port, url, quickcheck)
{
  local_var	soc, req, cod, buf;
  #display("check_win_dir_trav(port=", port, ", url=", url, ", quickcheck=", quickcheck, ")\n");

  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);

  if (quickcheck)
  {
    if (ereg(pattern:"^HTTP/.* 200 ", string:buf)) return (1);
    return (0);
  }

  if ( ("ECHO" >< buf)          || ("SET " >< buf)             ||
       ("export" >< buf)        || ("EXPORT" >< buf)           ||
       ("mode" >< buf)          || ("MODE" >< buf)             ||
       ("doskey" >< buf)        || ("DOSKEY" >< buf)           ||
       ("[boot loader]" >< buf) || ("[fonts]" >< buf)          ||
       ("[extensions]" >< buf)  || ("[mci extensions]" >< buf) ||
       ("[files]" >< buf)       || ("[Mail]" >< buf)           ||
       ("[operating systems]" >< buf)              )
  {
    return(1);
  }
  return(0);
}

#
#
#
function is_cgi_installed_ka(item, port)
{
 local_var r, no404, dir, slash, dirs;

 if(item[0] != "/")
 {
  dirs = cgi_dirs();
  slash = "/";
 }
 else
 {
  dirs = make_list("");
  slash = "";
 }
 
 foreach dir (dirs)
 {
 r = http_keepalive_send_recv(port:port, data:http_get(item:dir + slash + item, port:port));
 if( r == NULL ) return NULL;

 no404 = get_kb_item(string("www/no404/", port));

 if(ereg(pattern:"^HTTP.* 200 .*", string:r))
 {
  if(no404)
  {
   if(tolower(no404) >!< tolower(r))return(1);
  }
  else return(1);
  } 
 }
 return(0);
}

#
  
function get_http_page(port, url, redirect)
{
  local_var	r, u, v, i, l, seen_loc, n;

  if (isnull(redirect))
    n = 32;
  else if (redirect <= 0)
    n = 1;
  else
    n = redirect + 1;

  u = url;
  for (i = 0; i < n; i ++)	# Limited iterations to avoid traps
  {
    seen_loc[u] = 1;
    r = http_keepalive_send_recv(port: port, 
				data: http_get(port: port, item: u));
    if (isnull(r)) return NULL;

    if (r =~ "^HTTP/1\.[01] +30[0-9] .*")
    {
      v = eregmatch(pattern: "\r\nLocation: *([^ \t\r\n]+)[ \t]*[\r\n]+",
		string: r, icase: 1);
      if (isnull(v)) return NULL;	# Big problem
      l = v[1];
      if (seen_loc[l]) return NULL;
      seen_loc[l] = 1;
    }
    else if (r =~ "^HTTP/1\.[01] +200 ")
    {
      r = strstr(r, '\r\n\r\n');
      r = substr(r, 4);
      return r;
    }
    else	# Code 4xx or 5xx
      return NULL;
  }
  # Loop?
  return NULL;
}
