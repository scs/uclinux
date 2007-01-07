#
# This script was written by Patrick Naubert
# This is version 2.0 of this script.
#
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#	- warning with the version
#	- detection of other version
#	- default port for single test
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10342);
 script_version ("$Revision: 1.8 $");
 name["english"] = "Check for VNC";
 name["francais"] = "Check for VNC";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is running VNC.
VNC permits a console to be displayed remotely.

Solution: Disable VNC access from the network by 
using a firewall, or stop VNC service if not needed.

Risk factor : Medium";



 desc["francais"] = "
Le serveur distant fait tourner VNC.
VNC permet d'acceder la console a distance.

Solution: Protégez l'accès à VNC grace à un firewall,
ou arretez le service VNC si il n'est pas desire.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for VNC";
 summary["francais"] = "Vérifie la présence de VNC";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Patrick Naubert",
                francais:"Ce script est Copyright (C) 2000 Patrick Naubert");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/vnc", 5900, 5901, 5902);
 exit(0);
}

#
# The script code starts here
#

function probe(port)
{
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   r = recv(socket:soc, length:1024);
   version = egrep(pattern:"^RFB 00[0-9]\.00[0-9]$",string:r);
   if(version)
   {
      security_warning(port);
      security_warning(port:port, data:string("Version of VNC Protocol is: ",version));
   }
   close(soc);
  }
 }
}

port = get_kb_item("Services/vnc");
if(port)probe(port:port);
else
{
 for (port=5900; port <= 5902; port = port+1) {
  probe(port:port);
 }
}
