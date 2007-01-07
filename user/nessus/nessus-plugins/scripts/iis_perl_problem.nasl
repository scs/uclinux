#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# See:
# Date:  29 Dec 2001 18:53:39 -0000
# From: "antoan miroslavov" <shaltera@yahoo.com>
# To: bugtraq@securityfocus.com
# Subject: Active Perl path reveal
#

if(description)
{
 script_id(10120);
 script_version ("$Revision: 1.20 $");
 script_bugtraq_id(194);
 script_cve_id("CAN-1999-0450");
 name["english"] = "IIS perl.exe problem";
 name["francais"] = "IIS perl.exe problem";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
obtain the physical location of a
virtual web directory of this host by 
issuing the command :

	GET /scripts/no-such-file.pl HTTP/1.0
	
An attacker may use this flaw to gain more information about the remote
host, and hence make more focused attacks.

Solution : Use perlis.dll instead of perl.exe.

Risk factor : Low";

 desc["francais"] = "Il s'est avéré possible
d'obtenir l'emplacement physique du
dossier web virtuel de ce serveur
en entrant la commande :

	GET /scripts/no-such-file.pl HTTP/1.0
	
D'habitude, moins les pirates en savent sur
votre système, mieux il se porte, donc vous
devriez corriger ce problème.

Solution : utilisez perlis.dll plutot que
perl.exe.

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
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
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
  d = http_get(item:"/scripts/no-such-file.pl", port:port);
  send(socket:soc, data:d);
  r = http_recv(socket:soc);
  r = tolower(r);
  if("perl script" >< r)security_warning(port);
  http_close_socket(soc);
 }
}
