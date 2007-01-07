#
# written by Renaud Deraison
#
# Subject: paFileDB 3.x SQL Injection Vulnerability
# From: <ersatz@unixhideout.com>
# To: bugtraq@securityfocus.com
# Subject: XSS vulnerabilites in Pafiledb


if (description)
{
 script_id(11479);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(6021);
 
 script_name(english:"paFileDB XSS");
 desc["english"] = "
The remote pafiledb.php is vulnerable to a cross site scripting
attack.

An attacker may use this flaw to steal the cookies of your users


Solution : Upgrade to paFileDB 3.0
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if pafiledb is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list( cgi_dirs(), "");
		


foreach d (dir)
{
 url = string(d, '/pafiledb.php?action=download&id=4?"<script>alert(foo)</script>"');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))exit(0);

 if("<script>alert(foo)</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}

