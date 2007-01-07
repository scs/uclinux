#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10836);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(3702);
 script_cve_id("CVE-2001-1199");
 
 name["english"] = "Agora CGI Cross Site Scripting";
 name["francais"] = "Agora CGI Cross Site Scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
 Agora is a CGI based e-commerce package. Due to poor input validation, 
 Agora allows an attacker to execute cross-site scripting attacks. 
 For example:

http://www.example.com/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML

Solution : At the time of writing this test, no solution was available 
for this problem. However, a new version of Agora may become available 
at http://www.agoracgi.com. Please check the Agora CGI web site or 
contact your vendor for the latest version.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Agora CGI Cross Site Scripting";
 
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
 
installed = is_cgi_installed(item:"/store/agora.cgi", port:port);
if (!installed) exit(0);

 req = http_get(item:"/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("<SCRIPT>alert(document.domain)</SCRIPT>" >< r)	
 	security_hole(port);

 }
}
