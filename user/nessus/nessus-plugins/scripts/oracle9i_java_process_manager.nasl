#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10851);
 script_version("$Revision: 1.6 $");
 script_cve_id("CAN-2002-0563");
 script_bugtraq_id(4293);
 name["english"] = "Oracle 9iAS Java Process Manager";
 name["francais"] = "Oracle 9iAS Java Process Manager";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS, it is possible to access the 
Java Process Manager anonymously. Access to this page should be restricted.


Solution: 
Restrict access to /oprocmgr-status in httpd.conf

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle9iAS Java Process Manager";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(get_port_state(port))
{ 
# Make a request for /oprocmgr-status

 req = http_get(item:"/oprocmgr-status", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Module Name" >< r)	
 	security_hole(port);

 }
}
