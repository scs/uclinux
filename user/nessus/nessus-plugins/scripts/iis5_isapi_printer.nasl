#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10661);
 script_cve_id("CVE-2001-0241");
 script_version ("$Revision: 1.16 $");
 
 
 name["english"] = "IIS 5 .printer ISAPI filter applied";
 name["francais"] = "IIS 5 .printer ISAPI filter applied";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
IIS 5 has support for the Internet Printing Protocol(IPP), which is 
enabled in a default install. The protocol is implemented in IIS5 as an 
ISAPI extension. At least one security problem (a buffer overflow)
has been found with that extension in the past, so we recommend
you disable it if you do not use this functionality.

Solution: 
To unmap the .printer extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .printer from the list.

Reference : http://online.securityfocus.com/archive/1/181109

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for IIS5 .printer ISAPI filter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore",
		francais:"Ce script est Copyright (C) 2001 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

# Actual check starts here...
# Check makes a request for NULL.printer

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 req = http_get(item:"/NULL.printer", port:port);
 
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Error in web printer install" >< r)	
 	security_warning(port);

 }
}
