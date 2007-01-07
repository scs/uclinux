#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10352);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(1063);
 script_cve_id("CVE-2000-0236");
 name["english"] = "Netscape Server ?wp bug";
 name["francais"] = "Netscape Server ?wp bug";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting a URL with special tags such as '?ws-cs-dump' 
appended to it makes some Netscape servers dump the listing 
of the page directory, thus revealing the existence of potentially 
sensitive files to an attacker.

Risk factor : Medium/High

Solution : disable the 'web publishing' feature of your server";

 desc["francais"] = "Demander une URL finissant par '?wp-cs-dump' 
force certains serveurs Netscape à afficher le contenu du répertoire
de la page, montrant ainsi des fichiers potentiellement sensibles.

Facteur de risque : Moyen/Elevé.

Solution : désactivez le 'web publishing'";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Make a request like http://www.example.com/?wp-cs-dump";
 summary["francais"] = "Fait une requête du type http://www.example.com/?wp-cs-dump";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(data:req, port:port);
if(res == NULL || "<title>index of /</title>" >< tolower(res))exit(0);

tags = make_list("?wp-cs-dump", "?wp-ver-info", "?wp-html-rend", "?wp-usr-prop",
"?wp-ver-diff", "?wp-verify-link", "?wp-start-ver", "?wp-stop-ver", "?wp-uncheckout");

foreach tag (tags)
{
  req = http_get(item:"/" + tag, port:port);
  res = http_keepalive_send_recv(data:req, port:port);
  
  if( res == NULL ) exit(0);
  if("<title>index of /</title>" >< tolower(res)) 
  	{
		security_hole(port);
	}
  
}
