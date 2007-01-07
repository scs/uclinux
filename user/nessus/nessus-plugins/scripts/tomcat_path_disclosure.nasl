#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10807);
script_cve_id("CAN-2000-0759");
 script_bugtraq_id(1531);
 script_version ("$Revision: 1.12 $");
 name["english"] = "Jakarta Tomcat Path Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
Tomcat will reveal the physical path of the 
webroot when asked for a .jsp file using a specially
crafted request.

An attacker may use this flaw to gain further knowledge
about the remote filesystem layout.

Solution : Upgrade to a later software version.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Tomcat Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# According to this message:
#   Date:  Thu, 22 Nov 2001 17:32:20 +0800
#   From: "analysist" <analysist@nsfocus.com>
#   To: "bugtraq@securityfocus.com" <bugtraq@securityfocus.com>
#   Subject: Hi
# Jakarta Tomcat also reveals the web server install path if we get:
# /AAA...A.jsp  (223 x A)
# /~../x.jsp


include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 8080;
if(get_port_state(port))
{ 
 req = http_get(item:string("/:/x.jsp"), port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 
 if("Tomcat" >< r)
  {
  path = ereg_replace(pattern:".*HTTP Status 404 - ([^<]*) .The.*",
		    string:r,
		    replace:"\1");
  if(ereg(string:path, pattern:"[A-Z]:\\.*", icase:TRUE))security_warning(port);
  }
 }
}
