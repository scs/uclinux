#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10597);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CAN-2001-0223");
 

 name["english"] = "wwwwais";
 name["francais"] = "wwwwais";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'wwwwais' CGI is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'wwwwais' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/wwwwais";
 summary["francais"] = "Vérifie la présence de /cgi-bin/wwwwais";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);



if(safe_checks())
{
 foreach dir (cgi_dirs())
 {
 if(is_cgi_installed_ka(item:string(dir, "/wwwwais"), port:port))
 {
  report = "The CGI 'wwwwais' is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : remove it from /cgi-bin.

Risk factor : Serious";
 security_hole(port:port, data:report);
  } 
 }
 exit(0);
}




foreach dir (cgi_dirs())
{
 file = string(dir, "/wwwwais?version=123&", crap(4096));
 req = http_get(item:file, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("memory violation" >< r)
	security_hole(port);
}
