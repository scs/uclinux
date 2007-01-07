# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# $Revision: 1.32 $

function register_service(port, proto)
{
  local_var	k;
  if(known_service(port:port))
   return(0);
   
  k = string("Known/tcp/", port);
  set_kb_item(name: k, value: proto);
  k = string("Services/", proto);
  set_kb_item(name: k, value: port);
  #display("register_service: port=", port, ", proto=", proto, "\n");
}

# This function may fork!
function known_service(port)
{
  local_var	k, p;
  k = string("Known/tcp/", port);
  p = get_kb_item(k);
  #if (p) { display("Known service on port ", port, "\n"); }
  #else { display("Unknown service on port ", port, "\n"); }
  return p;
}

# This function does not fork!
function service_is_unknown(port)
{
  local_var	k, p;
  k = string("Known/tcp/", port);
  p = get_kb_list(k);
  #if (p) { display("Known service on port ", port, "\n"); }
  #else { display("Unknown service on port ", port, "\n"); }
  return isnull(p);
}



function set_mysql_version(port, version)
{
  local_var	sb;
  sb = string("mysql/version/", port);
  set_kb_item(name: sb, value: version);
}

function get_mysql_version(port)
{
  local_var	sb, vers, soc, result, MySQL_version, end_found;
  sb = string("mysql/version/", port);
  vers = get_kb_item(sb);
  if (vers) return(vers);
  else { # Get it on the fly.
    soc = open_sock_tcp(port);
    if(!soc) return(NULL);
    result = recv(socket:soc, length:1000);
    close(soc);
    if(strlen(result) < 6)return(NULL);
    if("is not allowed" >< result)return(NULL);
    if("is blocked" >< result) return(NULL);
    MySQL_version = "";
    if ((result[1] == raw_string(0x00)) && (result[2] == raw_string(0x00)) &&
       (result[3] == raw_string(0x00)) && ((ord(result[4]) > 8) && (ord(result[4]) < 12))){
      end_found = FALSE;
      for (i = 0; end_found == FALSE ; i = i + 1) {
        if (result[5+i] == raw_string(0x00)) {
          end_found = TRUE;
        } else {
          MySQL_version = string(MySQL_version, result[5+i]);
        }
      }
      set_mysql_version(port:port, version:MySQL_version);
      return(MySQL_version);
    }
  }
  return(NULL);
}

function get_unknown_banner(port, dontfetch)
{
  local_var	sb, banner, soc, req;
  sb = string("unknown/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  if (dontfetch) return(NULL);
  if (! get_port_state(port)) return (NULL);
  soc = open_sock_tcp(port);
  if(!soc) return (NULL);
  # I don't think that it makes sense to send an HTTP request
  #req = http_head(item:"/", port:port);
  #send(socket:soc, data:req);
  banner = recv(socket:soc, length:2048);
  close(soc);
  if (banner) set_kb_item(name: sb, value: banner);
  return(banner);
}

function set_unknown_banner(port, banner)
{
  local_var	sb;
  sb = string("unknown/banner/", port);
  set_kb_item(name: sb, value: banner);
}

#
# Get the banner for a given service
# You must also specify a default port, in case this is not in the kb
#
function get_service_banner_line(service, port)
{
  local_var	banner, soc, key, gport;
  gport = get_kb_item(string("Services/", service));
  if(!gport) gport = port;

  key = string(service, "/banner/", gport);
  banner = get_kb_item(key);
  
  if(!banner)
  {
    if(get_port_state(gport))
    {
      soc = open_sock_tcp(gport);
      if(soc)
      { 
	banner = recv_line(socket:soc, length:2048);
	close(soc);
      }
    }  
  }
  
  return(banner);
}
#
# Fast replacement for getrpcport() which uses the libc
#
function get_rpc_port(program, protocol, portmap)
{ 
 local_var	broken, req, soc, r, port;
 local_var	a, b, c, d, p_a, p_b, p_c, p_d, pt_a, pt_b, pt_c, pt_d;

 
 
 a = rand() % 255;
 b = rand() % 255;
 c = rand() % 255;
 d = rand() % 255;
 
 p_a = program / 16777216; 	p_a = p_a % 256;
 p_b = program / 65356; 	p_b = p_b % 256;
 p_c = program / 256;   	p_c = p_c % 256;
 p_d = program % 256;

 pt_a = protocol / 16777216; pt_a = pt_a % 256;
 pt_b = protocol / 65535   ; pt_b = pt_b % 256;
 pt_c = protocol / 256;    ; pt_c = pt_c % 256;
 pt_d = protocol % 256;
 
 
 req = raw_string(a, 	b, 	c, 	d, 	# XID
 		  0x00, 0x00, 0x00, 0x00,	# Msg type: call
		  0x00, 0x00, 0x00, 0x02,	# RPC Version
		  0x00, 0x01, 0x86, 0xA0,	# Program
		  0x00, 0x00, 0x00, 0x02,	# Program version
		  0x00, 0x00, 0x00, 0x03,	# Procedure
		  0x00, 0x00, 0x00, 0x00,	# Credentials - flavor
		  0x00, 0x00, 0x00, 0x00, 	# Credentials - length
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Flavor
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Length
		  
		  p_a,  p_b,  p_c,  p_d,	# Program
		  0xFF, 0xFF, 0xFF, 0xFF,	# Version (any)
		  pt_a, pt_b, pt_c, pt_d,	# Proto (udp)
		  0x00, 0x00, 0x00, 0x00	# Port
 		  );
	
	  
 if(isnull(portmap)){
   port = int(get_kb_item("rpc/portmap"));
   if(port == 0)port = 111;
   }
 else port = portmap;
 	  
	  
 broken = get_kb_item(string("/tmp/rpc/noportmap/", port));
 if(broken)return(0);
 
 	  
 soc = open_sock_udp(port);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 
 close(soc);
 if(!r)
 {
  set_kb_item(name:string("/tmp/rpc/noportmap/", port), value:TRUE);
  return(0);
 }
 
 if(strlen(r) < 28)
  return(0);
 else
  {
   p_d = ord(r[27]);
   p_c = ord(r[26]);
   p_b = ord(r[25]);
   p_a = ord(r[24]);
   port = p_a;
   port = port * 256;
   port = port +p_b; 
   port = port * 256;
   port = port + p_c; 
   port = port * 256;
   port = port + p_d;
   return(port);
  }
}

#
function rand_str(length, charset)
{
  local_var	l, i, s, n;

  if (! charset) 
   charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  if (isnull(length))
    length = 8;
  l = strlen(charset);
  s = "";
  for (i = 0; i < length; i ++)
  {
    n = rand() % l;
    s += charset[n];
  }
  return s;
}



function add_port_in_list(list, port)
{
 local_var l;
 
 
 if(!get_port_state(port))
 {
  if(isnull(list))return make_list();
  else return list;
 }
 
 if(isnull(list))return make_list(port);
 
 foreach l (list)
 { 
  if(l == port)
   return list;
 }

 return make_list(list, port);
}

