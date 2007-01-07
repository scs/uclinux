#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10295);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(1808);
 script_cve_id("CAN-1999-0970");
 
 name["english"] = "OmniHTTPd visadmin exploit";
 name["francais"] = "Exploitation du cgi visadmin de OmniHTTPd";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "It is possible to fill the hard disk of a server
running OmniHTTPd by issuing the request :
	http://omni.server/cgi-bin/visadmin.exe?user=guest
This allows an attacker to crash your web server.
This script checks for the presence of the faulty CGI, but
does not execute it.

Solution : remove visadmin.exe from /cgi-bin.

Risk factor : Medium/High";

 desc["francais"] = "Il est possible de remplir le disque dur 
d'un serveur OmniHTTPd en faisant la requete suivante :
 	http://omni.server/cgi-bin/visadmin.exe?user=guest
Ce problème permet à un attaquant de faire planter votre server.
Ce script vérifie la présence du CGI coupable, mais ne l'execute
pas.

Solution : retirez visadmin.exe du dossier cgi-bin.

Facteur de risque : Moyen/Elevé";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Checks for the visadmin.exe cgi";
 summary["francais"] = "Vérifie la présence de visadmin.exe";
 
 script_summary(english:summary["english"],
 	 	francais:summary["francais"]);
 
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
# Script code
#

port = is_cgi_installed("visadmin.exe");
if(port)security_hole(port);
