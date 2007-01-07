# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# get_http_port (C) Georges Dagousset
# $Revision: 1.45 $

#
# That's for chunk-decoding
#
function __hex_value(num)
{
   if(num == "a")return(10);
   if(num == "b")return(11);
   if(num == "c")return(12);
   if(num == "d")return(13);
   if(num == "e")return(14);
   if(num == "f")return(15);
   return(int(num));
}


function hex2dec(xvalue)
{
 local_var ret, l, i, n, m;
  
 if(!xvalue)return(0);
 xvalue = tolower(xvalue);
 l = strlen(xvalue) - 2;
 
 ret = 0;
 m = 1;
 
 # Remove the trailing spaces
 while(xvalue[l - 1]==" ")l--;
 
 for(i=l;i>0;i--)
 {
  n = __hex_value(num:xvalue[i - 1]) * m;
  ret = ret + n;
  m = m * 16;
 }
 return(ret);
}

#---------------------------------------------------#

function get_http_banner(port)
{
  local_var soc, sb, banner, req, body;
  
  if (! get_port_state(port)) return (0);
  sb = string("www/real_banner/", port);
  banner = get_kb_item(sb);
  if(banner) return(banner);
  
  sb = string("www/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = http_open_socket(port);
  if(!soc) return (NULL);
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  banner = http_recv_headers(soc);
  #body = http_recv_body(socket:soc, headers: banner);
  http_close_socket(soc);
  if(banner)
  {
   set_kb_item(name: sb, value: banner);
  }
  return(banner);
}

# Submitted by Georges Dagousset
# Usage: port = get_http_port(default:80);
function get_http_port(default)
{
  local_var	port, banner;
  port = get_kb_item("Services/www");
  if(! port) port = default;
  banner = get_http_banner(port: port);
  if (! banner) exit(0);
  return(port);
}

# (C) Georges Dagousset
# Usage:
# banner = get_http_banner(port:port);
# if (php_ver_match(banner:banner, 
#     pattern:".*PHP/((3.*)|(4\.0.*)|(4\.1\.[01].*))"))
#       security_hole(port);
#
function php_ver_match(banner, pattern) 
{
  local_var	line;
  line = egrep(pattern:"^Server:.*", string:banner);
  if(ereg(pattern:pattern, string:line))return(1);
  else
  {
    line = egrep(pattern:"^X-Powered-By:.*", string:banner);
    if(ereg(pattern:pattern, string:line))return(1);
  }
  return(0);
}

function http_is_dead(port, retry)
{
  local_var	soc, url, req, code, h, h2, b;
  
  if(!retry)retry = 0;

  soc = http_open_socket(port);
  while (!soc && i++ < retry)
  {
    sleep(1);
    soc = http_open_socket(port);
  }
  if (! soc) return (1);
  # NB: http_head does not work against SWAT & VNC (& probably others...)
  url = string("/NessusTest", rand(), ".html");
  req = http_get(item: url, port:port);
  
  send(socket:soc, data:req);
  code = recv_line(socket:soc, length: 1024);
  if (code)
  {
    h = http_recv_headers(soc);
    h2 = string(code, h);
    b = http_recv_body(socket: soc, headers: h2);
  }
  http_close_socket(soc);
  if (! code) return (1);
  # 500: internal server error; 502: Bad gateway; 503: service unavailable
  if (ereg(pattern: "^50[23]", string: code)) return(1);
  return (0);
}

# This function was originaly written by SecurITeam in 
# badblue_directory_traversal.nasl
# I (=MA) enhanced it.
# NB: it works with AUTOEXEC.BAT, WIN.INI and BOOT.INI
# quickcheck should be set to 0 if the server does not return clean 404 code,
# i.e., if "www/no404/"+port is defined in the KB

function do_check_win_dir_trav(port, url, quickcheck)
{
  local_var	soc, req, cod, buf;
  #display("check_win_dir_trav(port=", port, ", url=", url, ", quickcheck=", quickcheck, ")\n");
  soc = http_open_socket(port);
  if(! soc)
  {
   # display("check_win_dir_trav: cannot open socket to ", port, "\n");
    return (0);
  }

  req = http_get(item:url, port:port);
  send(socket:soc, data:req);
  cod = recv_line(socket: soc, length: 80);
  buf = http_recv(socket:soc, code: cod);
  http_close_socket(soc);

  if (quickcheck)
  {
    if (" 200 " >< cod) return (1);
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

function check_win_dir_trav(port, url, quickcheck)
{
 if(do_check_win_dir_trav(port:port, url:url + rand(), quickcheck:quickcheck))
	return NULL;
 else
	return do_check_win_dir_trav(port:port, url:url, quickcheck:quickcheck);
}


# This function does not return the headers!
# So 'length' parameter does not include headers length, even if we 
# have to read them. Anyway, this parameter will be ignored if Content-length
# is set

function http_recv_body(socket, headers, length)
{
  local_var	h, cl, l, min, max, x, n;
  if (!headers)
  {
    h = http_recv_headers(socket);
  }
  else
  {
    h = headers;
  }

  l = -1;
  cl = egrep(pattern:"^Content-length: *[0-9]+", string: h, icase: 1);
  if(cl)
  {
    l = ereg_replace(pattern: "Content-length: *([0-9]+).*", replace:"\1",
		string: cl, icase: 1);
  }
  max = 0;
  min = 0;
  

  if(l < 0 && egrep(pattern:"^transfer-encoding: chunked", string:h, icase:TRUE))
  {
   local_var tmp, body;
   body = "";
 
   while(1)
   {
   tmp = recv_line(socket:socket, length:4096);
   l = hex2dec(xvalue:tmp);
   body  = string(body, recv(socket:socket, length:l+2, min:l+2));
   if(l == 0){
   	return(string(h, body)); # This is expected - don't put this line before the previous
	}
   }
  }
  
  
  if (length) max = length;
  if (l) min = int(l);
  if (l > max) max = l;
  if (! max)
  {
    #display("http_recv_body: bogus or no Content-length field, and no 'length' paramater set! Defaulting to 8 KB\n");
    max = 8192;
  }
  #display("http_recv_body: min=", min, "; max=", max, "\n");
  if (min > 0)
  {
    x = recv(socket: socket, length: max, min: min);
  }
  else
  {
    n = recv(socket: socket, length: max);
    x = n;
    while ( strlen(n) == max )
    {
     n = recv(socket: socket, length: max);
     x += n;
     if( strlen(x) > 1024*1024 ){
	break;
	}
    }
    	
  }
  return(x);
}

# This function reads everything
# Note that bodylength will be ignored if the Content-length field is set

function http_recv(socket, code)
{
  local_var	h, b, l;
  if (code)
  {
    h = code;
    repeat
    {
      l = recv_line(socket: socket, length: 2048);
      h = h + l;
    }
    until (! h || h =~ '[\r\n]+');
  }
  else
  {
    h = http_recv_headers(socket);
  }
  if(!h)return(NULL);
  b = http_recv_body(socket: socket, headers: h, length:0);
  return (string(h, "\r\n", b));
}

function http_recv_length(socket, bodylength)
{
  local_var	h, b;
  h = http_recv_headers(socket);
  b = http_recv_body(socket: socket, headers: h, length: bodylength);
  return (string(h, "\r\n", b));
}



function cgi_dirs()
{
 local_var kb;
 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb))kb = make_list("/cgi-bin", "/scripts");
 else kb = make_list(kb);
 
 return(kb); 
}

