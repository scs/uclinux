#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10037);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(936);
 script_cve_id("CAN-2000-0079");
 name["english"] = "CERN httpd problem";
 name["francais"] = "CERN httpd problem";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
get the physical location of a
virtual web directory of this host by 
issuing the command :

	GET /cgi-bin/ls HTTP/1.0
	
Usually, the less the attacker knows about your
system, the better it feels, so you should
correct this problem.

Solution : use Apache (www.apache.org) since
           CERN httpd is no longer maintained

Bugtraq ID : 936
Risk factor : Low";

 desc["francais"] = "Il s'est avéré possible
d'obtenir l'emplacement physique du
dossier web virtuel de ce serveur
en entrant la commande :

	GET /cgi-bin/ls HTTP/1.0
	
D'habitude, moins les pirates en savent sur
votre système, mieux il se porte, donc vous
devriez corriger ce problème.

Solution : utilisez Apache (www.apache.org)
           puisque le CERN httpd n'est plus
	   maintenu

ID Bugtraq : 936
Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to find the location of the remote web root";
 summary["francais"] = "Essaye de trouver le chemin d'accès à la racine web distante";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/cern");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  d = string(dir, "/ls");
  req = http_get(item:d, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  r = tolower(r);
  if(" neither '/" >< r){
  	security_warning(port);
	exit(0);
	}
}

