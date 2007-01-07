#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10153);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0269");
 name["english"] = "Netscape Server ?PageServices bug";
 name["francais"] = "Netscape Server ?PageServices bug";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "Requesting an URL with '?PageServices' appended to
it makes some Netscape servers dump the listing of the page 
directory, thus revealing potentially sensitive files to an attacker.

Risk factor : Medium/High

Solution : Upgrade your Netscape server or turn off indexing";

 desc["francais"] = "Demander une URL finissant par '?PageServices' 
force certains serveurs Netscape à afficher le contenu du répertoire
de la page, montrant ainsi des fichiers potentiellement sensibles.

Facteur de risque : Moyen/Elevé.

Solution : Mettez à jour votre serveur Netscape ou désactivez l'indexage";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Make a request like http://www.example.com/?PageServices";
 summary["francais"] = "Fait une requête du type http://www.example.com/?PageServices";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  seek = "<title>index of /</title>";
  
  
  buffer = http_get(item:"/", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  data_low = tolower(data);
  if(seek >< data_low)exit(0);
  
  soc = http_open_socket(port);
  buffer = http_get(item:"/?PageServices", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  data_low = tolower(data);
  
  if(seek >< data_low)
  {
   security_hole(port);
  }
 }
}
