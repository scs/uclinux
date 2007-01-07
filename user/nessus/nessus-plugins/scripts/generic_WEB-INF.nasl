#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11037);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(5119);
 name["english"] = "WEB-INF folder accessible";
 name["francais"] = "WEB-INF folder accessible";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = " This vulnerability affects the Win32 versions of multiple j2ee servlet
containers / application servers. By making a particular request to the
servers in question it is possible to retrieve files located under
the 'WEB-INF' directory.

For example:

www.someserver.com/WEB-INF./web.xml

or

www.someserver.com/WEB-INF./classes/MyServlet.class

Solution: 

Contact your vendor for the appropriate patch.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for WEB-INF folder access";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
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
 req = http_get(item:"/WEB-INF./web.xml", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("web-app"); 
 confirmed_too = string("?xml");
 if ((confirmed >< r) && (confirmed_too >< r)) 	
 	security_hole(port);

 }
}

