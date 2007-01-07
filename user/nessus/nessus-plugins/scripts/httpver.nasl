#
# Copyright 2000 by Renaud Deraison <deraison@nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10582);
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "HTTP version spoken";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script determines which version of the HTTP protocol the remote
host is speaking

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "HTTP version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#



 port = get_kb_item("Services/www");
 if (!port) port = 80;

 if(get_port_state(port))
 {
  soc = http_open_socket(port);
  if(!soc)exit(0);
  req = string("GET / HTTP/1.1\r\n",
  	      "Connection: Close\r\n",
  	      "Host: ", get_host_name(), "\r\n",
	      "Pragma: no-cache\r\n",
	      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
	      "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n",
	      "Accept-Language: en\r\n",
	      "Accept-Charset: iso-8859-1,*,utf-8\r\n",
	      "\r\n"
	      ); 
  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  http_close_socket(soc);
  if("200" >< r)
   	{
  	set_kb_item(name:string("http/", port), value:"11");
	exit(0);
	}
  else 
  {
   soc = http_open_socket(port);
   if(!soc)exit(0);
   req = string("GET / HTTP/1.0\r\n\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:4096);
   http_close_socket(soc);
   if("200" >< r)
     {
   	set_kb_item(name:string("http/", port), value:"10");
	exit(0);
     }
   else
     {
       soc = http_open_socket(port);
       if(!soc)exit(0);
       req = string("GET /\r\n\r\n");
       send(socket:soc, data:req);
       r = recv_line(socket:soc, length:4096);
       http_close_socket(soc);
       if("200" >< r)
         {
           set_kb_item(name:string("http/", port), value:"09");
	   exit(0);
         }
     }
  }
 }


# The remote server does not speak http at all. We'll mark it as
# 1.0 anyway
if(port == 80)
{
 set_kb_item(name:string("http/", port), value:"10");
}
