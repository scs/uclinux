#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
#
#	- changed the request to GET / HTTP/1.0 (and not GET / HEAD/1.0)
#	- French translation
#	- script id
#	- changed family to Remote file access
#

if(description)
{
 script_id(10355);
script_cve_id("CVE-2000-0240");
 script_bugtraq_id(1067);
 script_version ("$Revision: 1.16 $");
 name["english"] = "vqServer web traversal vulnerability";
 name["francais"] = "vqServer web traversal vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
vqSoft's vqServer web server (version 1.9.9 and below) has been detected.
This version contains a security vulnerability that allows attackers to request any file,
even if it is outside the HTML directory scope.

For more information:
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html

Solution:
Upgrade to the latest version, available from: http://www.vqsoft.com.

Risk factor : Medium";

 desc["francais"] = "
Le serveur web distant est un serveur vqServer de vqSoft,
d'une version plus ancienne (ou égale) à 1.9.9. 
Celle-ci possède une vulnérabilité permettant à un pirate
d'obtenir des fichiers arbitraires sur ce système.

Plus d'informations :
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html

Solution : Mettez votre serveur à jour (http://www.vqsoft.com)

Facteur de risque : Moyen";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect vqServer's web traversal bug";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if (get_port_state(port))
{
 soctcp80 = http_open_socket(port);

 if (soctcp80)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp80, data:sendata);
  banner = http_recv(socket:soctcp80);
  http_close_socket(soctcp80);
  
  if ("Server: vqServer" >< banner)
  {
   resultrecv = strstr(banner, "Server: ");
   resultsub = strstr(resultrecv, string("\n"));
   resultrecv = resultrecv - resultsub;
   resultrecv = resultrecv - "Server: ";
   resultrecv = resultrecv - string("\n");
   
   if(egrep(string:resultrecv, pattern:"vqServer/(0\.|1\.([0-8]\.|9\.[0-9])"))
   {
    banner = string("vqServer version is : ");
    banner = banner + resultrecv;
    security_warning(port);
    security_warning(port:port, data:banner);
   }
  }
 }
}
