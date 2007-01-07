#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10165);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0045");
 script_bugtraq_id(686);
 
 
 name["english"] = "nph-test-cgi";
 name["francais"] = "nph-test-cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'nph-test-cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker get a listing
of the /cgi-bin directory, thus discovering which CGIs are installed
on the remote host.

Solution : remove it from /cgi-bin.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'nph-test-cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui d'obtenir
un listing the /cgi-bin, obtenant ainsi la liste des CGI installés
par le serveur.

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/nph-test-cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/nph-test-cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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

cgi = "nph-test-cgi";
port = is_cgi_installed(cgi);
if(port)security_warning(port);
