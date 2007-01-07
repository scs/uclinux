#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10744);
 script_version ("$Revision: 1.6 $");

 name["english"] = "VisualRoute Web Server Detection";
 script_name(english:name["english"]);

 desc["english"] = "
We detected the remote web server as being a VisualRoute web server. 
This server allows attackers to perform a traceroute to a third party's 
hosts without revealing themselves to the target of the traceroute.

Solution: Disable the VisualRoute web server, or block the web server's 
port number on your Firewall.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "VisualRoute Web Server Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 
 port = get_kb_item("Services/www");
 if (!port) port = 8000;

  banner = get_http_banner(port:port);
  if(!banner)exit(0);


  if (egrep(pattern:"^Server: VisualRoute (tm) ", string:banner))
  {
   security_warning(port);
  }


