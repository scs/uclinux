#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10740); 
 script_version ("$Revision: 1.9 $");
 name["english"] = "SiteScope Web Managegment Server Detect";
 script_name(english:name["english"]);

 desc["english"] = "The remote web server is running the SiteScope Management 
web server. This service allows attackers to gain sensitive information on 
the SiteScope-monitored server.

Sensitive information includes (but is not limited to): license number, 
current users, administrative email addresses, database username and 
password, SNMP community names, UNIX usernames and passwords, 
LDAP configuration, access to internal servers (via Diagnostic tools), etc.

Solution: Disable the SiteScope Managment web server if it is unnecessary, 
or block incoming traffic to this port.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "SiteScope Web Management Server Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8888);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/SiteScope/htdocs/SiteScope.html", port:port);
  send(socket:soc, data: req);

  buf = http_recv(socket:soc);
  #display(buf);
  if (("Freshwater Software" >< buf) && ("URL=SiteScope.html" >< buf))
  {
   security_warning(port:port);
   exit(0);
  }
  http_close_socket(soc);
 }
  else {
   exit(0);
 }
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  buf = http_recv(socket:soc);

  #display(buf);
  if (("URL=/SiteScope/htdocs/SiteScope.html" >< buf) && ("A HREF=/SiteScope/htdocs/SiteScope.html" >< buf))
  {
   security_warning(port);
   exit(0);
  }
  http_close_socket(soc);
 }
}

