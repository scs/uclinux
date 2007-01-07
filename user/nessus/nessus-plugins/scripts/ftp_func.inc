# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# $Revision: 1.18 $

function ftp_close(socket)
{
  local_var	r;

  if (send(socket: socket, data: string("QUIT\r\n")))
  {
    r = "550 ";
    while ((r) && ! ("221 " >< r))
    {
      r = recv_line(socket:socket, length: 1024);
      #display ("QUIT answer = ", r);
    }
  }
  close(socket);
}

function get_ftp_banner(port)
{
 local_var lines, sb, banner, soc, str;
 
 lines = 0;
  sb = string("ftp/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  if (! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if(!soc) return(NULL);
  banner = recv_line(socket:soc, length:1024);
  if(ereg(string:banner, pattern:"^220-"))
  {
   str =  recv_line(socket:soc, length:1024);
   banner = string(banner, str);
   while(ereg(string:str, pattern:"^220-"))
   {
    str =  recv_line(socket:soc, length:1024);
    banner = string(banner, str);
    lines ++;
    if( lines > 255)break;
   }
  }
  ftp_close(socket: soc);
  if(strlen(banner)) set_kb_item(name: sb, value: banner);
  return(banner);
}


function ftp_recv_line(socket)
{
 local_var	n, r;
 n = 0;
 r = recv_line(socket:socket, length:65535);
 if(strlen(r) < 4) 
  return(r);
  
 while(r[3] == "-")
 {
  n ++;
  r = recv_line(socket:socket, length:65535);
  if(n > 255)
   return(NULL);
 }
 return(r);
}


function ftp_recv_listing(socket)
{
 local_var	n, r, buf;
 n = 0;
 r = recv_line(socket:socket, length:65535);
 buf = r;
 while(strlen(r))
 {
  n ++;
  if(n > 4096)
   return(NULL);
  r = recv_line(socket:socket, length:65535);
  buf += r; 
 }
 return buf;
}

function ftp_recv_data(socket, line)
{
 local_var buf, bytes, min;
 
 if(line != NULL )
 {
  bytes = ereg_replace(pattern:"^150.*\(([0-9]*) .*\)", string:line, replace:"\1");
 }
 
 if(!bytes){ bytes = 8192; min = 1; }
 else { min = int(bytes); bytes = int(bytes); }
 
 return recv(socket:socket, min:bytes, length:bytes);
}
