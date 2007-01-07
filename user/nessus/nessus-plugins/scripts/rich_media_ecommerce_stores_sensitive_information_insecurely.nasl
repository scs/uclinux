#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

if(description)
{
 script_id(10874);
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(4172);

 name["english"] = "Rich Media E-Commerce Stores Sensitive Information Insecurely";
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability in Rich Media's JustAddCommerce  allows attackers 
to gain sensitive client information by accessing a log file that is stored 
in an insecure manner

Risk factor : Medium
Solution : contact the vendor for a patch
See also : http://www.securiteam.com/windowsntfocus/5XP0N0A6AU.html";


 script_description(english:desc["english"]);
 
 summary["english"] = "Rich Media E-Commerce Stores Sensitive Information Insecurely";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SecurITeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

# Check starts here

function check(req)
{
  req = http_get(item:req, port:port); 
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  if (("HttpPost Retry" >< buf) && ("checkouthtml" >< buf) && ("password" >< buf))
  {
   	security_hole(port:port);
	exit(0);
  }
 return(0);
}

port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);


check(req:"/rtm.log");
foreach dir (cgi_dirs())
{
check(req:string(dir, "/rtm.log"));
}
