#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10327);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(977);
 script_cve_id("CVE-2000-0149");
 
 name["english"] = "Zeus shows the content of the cgi scripts";
 name["francais"] = "Zeus shows the content of the cgi scripts";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running the Zeus WebServer.

Version 3.1.x to 3.3.5 of this web server are vulnerable
to a bug which allows an attacker to view the source code
of CGI scripts.

Solution : Make sure you are running Zeus 3.3.5a or greater.
Risk factor : Serious";



 desc["francais"] = "
Le serveur distant fait tourner Zeus WebServer.

Les version 3.1.x jusqu'a 3.3.5 contiennent un bug qui permet
à n'importe qui de télécharger le contenu des scripts
CGIs.

Solution : Assurez-vous que vous faites tourner Zeus 3.3.5a ou mieux
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for Zeus";
 summary["francais"] = "Vérifie la présence de Zeus";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zeus");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
 
if(banner)
{ 
  if(egrep(pattern:"Server *:.*Zeus/3\.[1-3][^0-9]", string:banner))
   security_hole(port);
}
