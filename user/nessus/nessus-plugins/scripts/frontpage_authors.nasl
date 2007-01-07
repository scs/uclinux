#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10078);
 script_version ("$Revision: 1.14 $");

 name["english"] = "Microsoft Frontpage 'authors' exploits";
 name["francais"] = "Exploits 'authors' Microsoft Frontpage"; 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server appears to be running with
Frontpage extensions and lets the file 'authors.pwd'
to be downloaded by everyone.

This is a security concern since this file contains
sensitive data.

Solution : Contact Microsoft for a fix.

Risk factor : Medium";

 desc["francais"] = "
Le serveur web distant semble tourner avec
des extensions Frontpage et laisse le fichiers
'authors.pwd' en libre accès.

C'est un problème puisque ce fichier contient
des informations sensibles.

Solution : Contactez Microsoft pour un patch.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of Microsoft Frontpage extensions";
 summary["francais"] = "Vérifie la présence des extensions Frontpage";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#

port = is_cgi_installed("/_vti_pvt/authors.pwd");
if(port)
{
 security_hole(port);
}
