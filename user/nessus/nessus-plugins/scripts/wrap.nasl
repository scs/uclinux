#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10317);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(373);
 script_cve_id("CVE-1999-0149");
 
 name["english"] = "wrap";
 name["francais"] = "wrap";
 name["deutsch"] = "wrap";
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "The 'wrap' CGI is installed. This CGI allows
anyone to get a listing for any directory with mode +755.


*** Note that all implementations of 'wrap' are not
*** vulnerable. See the relevant CVE entry.
   
Solution : remove it from /cgi-bin.

Risk factor : Low/Medium";


 desc["francais"] = "Le cgi 'wrap' est installé. Celui-ci permet
à n'importe qui d'obtenir un listing pour n'importe quel dossier
de mode +755.


*** Notez que toutes les implémentations de 'wrap'
*** ne sont pas vulnérables. Consultez la bonne
*** entrée CVE
   
Solution : retirez-le de /cgi-bin.

Facteur de risque : Faible/Moyen";

 desc["deutsch"] = "Das CGI 'wrap' ist installiert. Dieses CGI ermöglicht
jedem ein beliebiges Verzeichnis mit dem Modus +755 einzusehen.

Lösung: Löschen aus dem Verzeichnis /cgi-bin

Risikofaktor: Niedrig / Mittel";

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/wrap";
 summary["francais"] = "Vérifie la présence de /cgi-bin/wrap";
 summary["deutsch"] = "Überprüft auf Existenz von /cgi-bin/wrap"; 

 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
                deutsch:"Dieses Skript ist urheberrechtlich geschützt (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 family["deutsch"] = "CGI Mißbrauch";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

port = is_cgi_installed("wrap");
if(port)security_hole(port);

