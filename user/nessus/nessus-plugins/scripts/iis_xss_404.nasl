#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
#
# See the Nessus Scripts License for details
#
# admins who installed this patch would necessarily not be vulnerable to CAN-2001-1325

if(description)
{
 script_id(10936);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(4483);
 name["english"] = "IIS XSS via 404 error";
 name["francais"] = "IIS XSS via 404 error";
 script_name(english:name["english"], francais:name["francais"]);
 script_cve_id("CVE-2002-0148", "CAN-2002-0150");     # lots of bugs rolled into one patch...
 
 desc["english"] = "This IIS Server appears to vulnerable to one of the cross site scripting
attacks described in MS02-018. The default '404' file returned by IIS uses scripting to output a link to 
top level domain part of the url requested. By crafting a particular URL it is possible to insert arbitrary script into the
page for execution.

The presence of this vulnerability also indicates that you are vulnerable to the other issues identified in MS02-018 (various remote buffer overflow and cross site scripting attacks...)

References:
http://www.microsoft.com/technet/security/bulletin/MS02-018.asp
http://jscript.dk/adv/TL001/

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for IIS XSS via 404 errors";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

# Check makes a request for non-existent HTML file. The server should return a 404 for this request.
# The unpatched server returns a page containing the buggy JavaScript, on a patched server this has been
# updated to further check the input...

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 req = http_get(item:"/blah.htm", port:port);

 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 
 str1="urlresult";
 str2="+ displayresult +";

 if((str1 >< r) && (str2 >< r)) security_warning(port);
 }
}
