#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10793);
 script_version ("$Revision: 1.7 $");

 name["english"] = "Cobalt Web Administration Server Detection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote web server is the Cobalt Administration web server. 

This web server enables attackers to configure your Cobalt server 
if they gain access to a valid authentication username and password.

Solution: Disable the Cobalt Administration web server if 
you do not use it, or block inbound connections to this port.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Cobalt Web Administration Server Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 81);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:81);
foreach port (ports)
{
soc = http_open_socket(port);
if(soc)
 {
  req = http_get(item:"/admin/", port:port);
  send(socket:soc, data:req);
  buf = http_recv(socket:soc);
  http_close_socket(soc);
  #display(buf);
  if (("401 Authorization Required" >< buf) && (("CobaltServer" >< buf) || ("CobaltRQ" >< buf)) && ("WWW-Authenticate: Basic realm=" >< buf))
  {
  security_note(port);
  }
 }
}
