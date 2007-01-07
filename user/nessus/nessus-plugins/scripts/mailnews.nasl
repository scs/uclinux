
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10641);
 script_cve_id("CAN-2001-0271");
 script_bugtraq_id(2391);
 
 script_version ("$Revision: 1.7 $");
 name["english"] = "mailnews.cgi";
 name["francais"] = "mailnews.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'mailnews' cgi is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'mailnews' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of mailnews.cgi";
 summary["francais"] = "Vérifie la présence de mailnews.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

port = is_cgi_installed("mailnews.cgi");
if(port)
 security_warning(port);
