#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10601);
 script_cve_id("CAN-2001-1044");
 script_bugtraq_id(2198);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "Basilix includes download";
 name["francais"] = "Basilix includes download";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to download the include files on the remote
BasiliX webmail service.

An attacker may use these to obtain the MySQL authentication
credentials

Solution :  put a handler in your web server for the .inc and .class
files
Risk factor : Medium";


 desc["francais"] = "
Il est possible de télécharger les fichiers include du service
webmail BasiliX distant.

Un pirate peut utiliser ce problème pour obtenir
le compte d'accès à la base MySQL distant

Solution : mettez un handler dans votre serveur web pour le
faire traiter les pages .inc et .class

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of include files";
 summary["francais"] = "Vérifie la présence de fichiers d'include";
 
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

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


function get_file(file, port)
{
  req = http_get(item:file, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(r == NULL)exit(0);
  
  if("BasiliX" >< r)
   {
    if("This program is free software" >< r) 
     {
      security_hole(port);
      exit(0);
     }
   }
 return(0);
}


port = get_kb_item("Services/www");
if(!port) port = 80;

if(get_port_state(port))
{
 get_file(file:"/inc/sendmail.inc", port:port);
 get_file(file:"/class/mysql.class", port:port);
 
 foreach dir (cgi_dirs())
 {
 get_file(file:string(dir, "/inc/sendmail.inc"), port:port);
 get_file(file:string(dir, "/class/mysql.class"), port:port);
 }
}
