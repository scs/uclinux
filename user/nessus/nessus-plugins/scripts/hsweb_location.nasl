#
# This script was written by Renaud Deraison <deraison@nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10606);
 script_cve_id("CAN-2001-0200");
 script_bugtraq_id(2336);
 script_version ("$Revision: 1.7 $");
 name["english"] = "HSWeb document path";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to request the physical location of the remote
web root by requesting the folder :

	/cgi

An attacker may use this flaw to gain more knowledge about this
host.

Solution : Turn off directory browsing if your server allows it
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Retrieve the real path using /cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(get_port_state(port))
{
  req = http_get(item:"/cgi", port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = http_recv(socket:soc);
   http_close_socket(soc);
   
   if("Directory listing of" >< result)
   {
    security_warning(port);
    exit(0);
   }
  }
}

