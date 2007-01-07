#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
#	- french description
#	- solution
#	- script id

if(description)
{
 script_id(10354);
 script_bugtraq_id(1610);
 script_cve_id("CVE-2000-0766");
 script_version ("$Revision: 1.9 $");
 name["english"] = "vqServer administrative port";
 name["francais"] = "Port administratif de vqServer";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
vqSoft's vqServer administrative port is open. Brute force guessing of the 
username/password is possible, and a bug in versions 1.9.9 and below 
allows configuration file retrieval remotely.

For more information, see:
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html

Solution: close this port for outside access.

Risk factor : Medium";

 desc["francais"] = "
Le port administratif de vqServer de vqSoft est ouvert. Un pirate
peut tenter d'obtenir la combinaison login/password par force
brute, et un bug dans les version 1.9.9 et précédentes
permettent à quiconque de lire les fichiers de configuration
à distance.

Pour plus d'informations, voir :
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html

Solution : filtrez l'accès à ce port.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detect vqServer's administrative port";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 
 script_require_ports("Services/vqServer-admin", 9090);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/vqServer-admin");
if(!port)port = 9090;
if (get_port_state(port))
{
 soctcp9090 = http_open_socket(port);

 if (soctcp9090)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp9090, data:sendata);
  banner = http_recv(socket:soctcp9090);
  http_close_socket(soctcp9090);
  
  if (("Server: vqServer" >< banner) && ("WWW-Authenticate: Basic realm=/" >< banner))
  {
    resultrecv = strstr(banner, "Server: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "Server: ";
    resultrecv = resultrecv - "\n";
   
    banner = string("vqServer version is : ");
    banner = banner + resultrecv;
    security_warning(port);
    security_warning(port:port, data:banner);
  }
 }
}

