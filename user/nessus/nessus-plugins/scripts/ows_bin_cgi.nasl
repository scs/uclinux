#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# Changes by rd :
#
#	- script id
#	- french translation
#	- minor changes in the english description
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10348);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(1053);
 
 script_cve_id("CVE-2000-0169");
 name["english"] = "ows-bin";
 name["francais"] = "ows-bin";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = " 
Oracle's Web Listener (a component of the Oracle Application Server),
is installed and can be used by a remote attacker to run arbitrary 
commands on the web server.

Read more about this hole at:
http://www.securiteam.com/windowsntfocus/Oracle_Web_Listener_4_0_x_CGI_vulnerability.html


Solution : If 'ows-bin' is the default CGI directory used by the Oracle Application Server Manager,
then remove the ows-bin virtual directory or point it to a more benign directory.
If 'ows-bin' is not the default then verify that there are no batch files in this directory.

Risk factor : High";


  desc["francais"] = "
Oracle Web Listener (un composant de Oracle Application Server)
est installé et peut etre utilisé par un pirate pour executer
des commandes arbitraires sur le serveur.

Vous pouvez lire plus d'infos sur ce trou à :
http://www.securiteam.com/windowsntfocus/Oracle_Web_Listener_4_0_x_CGI_vulnerability.html

Solution : If 'ows-bin' est le dossier de CGI utilisé par Oracle Application
Server par défaut, alors enlevez le dossier virtuel ows-bin ou bien redirigez-le
vers un dossier plus bénin.
Si 'ows-bin' n'est pas à sa valeur par défaut, alors vérifiez qu'il n'y
a pas de fichiers de batch dans ce dossier
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if ows-bin is vulnerable";
 summary["francais"] = "Vérifie si ows-bin est vulnérable";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Noam Rathaus");
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

port = is_cgi_installed("/ows-bin/perlidlc.bat");
if(port)
{
  req = http_get(item:"/ows-bin/perlidlc.bat?&dir", port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = http_recv(socket:soc);
   http_close_socket(soc);
   if("ows-bin:" >< result)security_hole(port);
  }
}

