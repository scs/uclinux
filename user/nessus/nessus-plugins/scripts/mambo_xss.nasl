#
#  Written by K-Otik.com <ReYn0@k-otik.com>
#
#  Mambo Site Server 4.0.10 XSS attack
#
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <ertank@olympos.org> 
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns </archive/1/315554/2003-03-19/2003-03-25/1>
#

if (description)
{
 script_id(11441);
 script_bugtraq_id(7135);
 script_version ("$Revision: 1.4 $");

 script_name(english:"Mambo Site Server 4.0.10 XSS");
 desc["english"] = "
Mambo Site Server is an open source Web Content Management System. An attacker 
may use it to perform a cross site scripting attack on this host.


Solution: Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 k-otik.com");
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

dir = make_list(cgi_dirs(), "");
		


foreach d (dir)
{
 url = string(d, "/index.php?option=search&searchword=<script>alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
    "<script>alert(document.cookie);</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}
