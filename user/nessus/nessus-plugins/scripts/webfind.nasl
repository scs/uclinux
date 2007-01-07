#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10475);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(1487);
 script_cve_id("CVE-2000-0622");
 name["english"] = "Buffer overflow in WebSitePro webfind.exe";
 name["francais"] = "Dépassement de buffer dans webfind.exe de WebSite pro";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote CGI '/cgi-bin/webfind.exe' is vulnerable to
a buffer overflow when given a too long 'keywords' argument.

This problem allows an attacker to execute arbitrary code
as root on this host.

Solution : upgrade to WebSitePro 2.5 or delete this CGI
Risk factor : High";
	
 desc["francais"] = "
Le CGI distant '/cgi-bin/webfind.exe' est vulnérable à
un dépassement de buffer lorsqu'on lui donne un argument
'keywords' trop long.

Ce problème permet à un pirate d'executer du code arbitraire
sur ce serveur.

Solution : mettez website pro à jour en version 2.5 ou effacez de CGI
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "buffer overflow attempt";
 summary["francais"] = "essai de dépassement de buffer";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 # This test is harmless
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/websitepro");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
req = string(dir, "/webfind.exe?keywords=", crap(10));
req = http_get(item:req, port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 ", string:r))
{
 # No keep alive here
 req = string(dir, "/webfind.exe?keywords=", crap(2000));
 req = http_get(item:req, port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(!r)security_hole(port);
 }
}
