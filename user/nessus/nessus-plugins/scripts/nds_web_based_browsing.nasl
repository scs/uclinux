#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com> 
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10739); 
 script_cve_id("CAN-1999-1020");
 script_bugtraq_id(484);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "Novell Web Server NDS Tree Browsing";
 script_name(english:name["english"]);
 
 desc["english"] = "The Novell Web Server default ndsobj.nlm CGI (LCGI) was 
detected. This CGI allows browsing of the NDS Tree without any need for 
authentication.

Gaining access to the NDS Tree reveals sensitive information to an attacker.

Solution: Configure your Novell Web Server to block access to this CGI, 
or delete it if you do not use it.

For More Information: http://www.securiteam.com/securitynews/5XP0L1555W.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Novell Web Server NDS Tree Browsing";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
 
 dir[0] = "/lcgi";
 dir[1] = "/lcgi-bin";
 dir[2] = "/LCGI";
 dir[3] = "/apage/lcgi-bin";

 port = get_kb_item("Services/www");
 if (!port) port = 80;
 

if (get_port_state(port))
{
  for(i=0;dir[i];i=i+1)
  {
  data = http_get(item:dir[i], port:port);
  resultrecv = http_keepalive_send_recv(port:port, data:data);
  if(resultrecv == NULL ) exit(0);
  if ("Available NDS Trees" >< resultrecv)
  {
    security_hole(port:port);
    exit(0);
  }
 }
}
