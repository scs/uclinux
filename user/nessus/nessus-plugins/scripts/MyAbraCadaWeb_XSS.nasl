#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# Message-ID: <20030317202237.3654.qmail@www.securityfocus.com>
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-010] Path Disclosure & Cross Site Scripting Vulnerability in MyABraCaDaWeb


if (description)
{
 script_id(11417);
 script_bugtraq_id(7126, 7127);
 script_version ("$Revision: 1.5 $");

 script_name(english:"MyAbraCadaWeb Cross Site Scripting");
 desc["english"] = "
The remote host seems to be running MyAbraCadaWeb. An attacker
may use it to perform a cross site scripting attack on
this host, or to reveal the full path to its physical location.


Solution: Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
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

dir = make_list(cgi_dirs(), "");
		


foreach d (dir)
{
 url = "/index.php?module=pertinance&ma_ou=annuaire2liens&ma_kw=<script>alert(document.cookie)</script>";
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/1\.[01] 200 ", string:buf) &&
    "<script>alert(document.cookie)</script>" >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}
