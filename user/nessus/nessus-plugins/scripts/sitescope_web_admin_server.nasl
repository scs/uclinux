#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10741); 
 script_version ("$Revision: 1.7 $");
 name["english"] = "SiteScope Web Administration Server Detection";
 script_name(english:name["english"]);

 desc["english"] = "The remote web server is running the SiteScope Administration 
web server. This server enables attackers to configure your SiteScope product 
(Firewall monitoring program) if they gain access to a valid authentication 
username and password or to gain valid usernames and passwords using
a brute force attack.

Solution: Disable the SiteScope Administration web server if it is unnecessary,
or block incoming traffic to this port.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "SiteScope Web Administration Server Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 2525);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:2525);
foreach port (ports)
{
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  buf = http_recv(socket:soc);

  #display(buf);
  if (("401 Unauthorized" >< buf) && ("WWW-Authenticate: BASIC realm=" >< buf) && ("SiteScope Administrator" >< buf))
  {
   security_warning(port:port);
  }
  http_close_socket(soc);
 }
}
