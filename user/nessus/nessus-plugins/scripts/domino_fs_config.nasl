#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10058);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(881);
 script_cve_id("CAN-2000-0021");
 name["english"] = "Domino HTTP server exposes the set up of the filesystem";
 name["francais"] = "Le serveur HTTP Domino affiche la config du filesystem";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to get the absolute path leading to
the remote /cgi-bin directory by requesting a bogus
cgi (like : 'GET /cgi-bin/blah').

This problem can be used to obtain OS and installation
details.

Solution : Contact your vendor for a patch
Risk factor : Low";


 desc["francais"] = "
Il est possible d'obtenir le chemin absolu menant
au dossier cgi-bin en faisant une requete pour un CGI
bidon (tel que 'GET /cgi-bin/blah').

Ce problème peut etre exploité pour obtenir des détails
sur votre OS et votre installation.

Solution : Contactez votre vendeur pour un patch
Facteur de risque : faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "obtains absolute path to cgi-bin";
 summary["francais"] = "obtient le chemin vers cgi-bin";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl","httpver.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/cgi-bin/just_a_test_ignore",
  		 port:port);
  send(socket:soc, data:req);
  s = http_recv(socket:soc);
  http_close_socket(soc);
  if("domino/cgi-bin" >< s)security_warning(port);
 }
}
