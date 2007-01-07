#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10121);
 script_version ("$Revision: 1.14 $");

 name["english"] = "/scripts directory browsable";
 name["francais"] = "Dossier /scripts listable";

 script_name(english:name["english"],
	     francais:name["francais"]);
 
 # Description
 desc["english"] = "The /scripts directory is browsable.
This gives an attacker valuable information about
which default scripts you have installed and also whether
there are any custom scripts present which may have vulnerabilities.

Solution : Disable directory browsing using the IIS MMC.

Risk factor : Medium";

 desc["francais"] = "Le répertoire /scripts est 
listable. Cela permet à un pirate de chercher
plus facilement et plus efficacement des 
scripts potentiellements vulnérables, et de
découvrir vos scripts maisons qui peuvent
avoir des problèmes de sécurité.

Solution : désactivez l'option de dossiers listables
dans IIS.

Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);

 # Summary
 summary["english"] = "Is /scripts/ listable ?";
 summary["francais"] = "/scripts/ est-il listable ?";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);

 # Category
 script_category(ACT_GATHER_INFO);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl");
 
 # Family
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"],
 	       francais:family["francais"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

# The attack starts here
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
 data = http_get(item:"/scripts", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  code = recv_line(socket:soc, length:1024);
  buf = http_recv(socket:soc);
  buf = tolower(buf);
  must_see = "<title>/scripts";
  
  if((" 200 " >< code)&&(must_see >< buf))security_warning(port);
  http_close_socket(soc);
 }
}
