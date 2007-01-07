#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10291);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0177");
 name["english"] = "uploader.exe";
 name["francais"] = "uploader.exe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'uploader.exe' CGI is installed. This CGI has
a well known security flaw that lets anyone upload arbitrary
CGI on the server, and then execute them.

Solution : remove it from /cgi-win.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'uploader.exe' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui
d'uploader des CGI arbitraires puis de les executer.

Solution : retirez-le de /cgi-win.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-win/uploader.exe";
 summary["francais"] = "Vérifie la présence de /cgi-win/uploader.exe";
 
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

cgi = "/cgi-win/uploader.exe";
port = is_cgi_installed(cgi);
if(port)security_hole(port);

