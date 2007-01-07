#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# Modified by Renaud Deraison <deraison@cvs.nessus.org> :
#	- report modified
#	- removed the warning saying the linuxconf was running,
#	  due to redundancy with find_service.nes output
#	- script_dependencie() added
#	- script_require_ports() changed
#	- French translation
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10135);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CAN-2000-0017"); 
 name["english"] = "LinuxConf grants network access";
 name["francais"] = "LinuxConf autorise les accès à distance";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Linuxconf is running (Linuxconf is a sophisticated 
administration tool for Linux) and is granting network
access at least to the host nessusd is running onto.

LinuxConf is suspected to contain various buffer overflows,
so you should not let allow networking access to anyone.


Solution: Disable Linuxconf access from the network by 
using a firewall, if you do not need Linuxconf use the 
Linuxconf utility (command line or XWindows based version) 
to disable it.

See additional information regarding the dangers of 
keeping this port open at :
http://www.securiteam.com/exploits/Linuxconf_contains_remotely_exploitable_buffer_overflow.html

Risk factor : Medium";

 desc["francais"] = "
LinuxConf (un outil d'administration distante sophistiqué)
tourne et autorise son accès par le réseau au moins au
système sur lequel nessusd tourne.

LinuxConf est suspecté de contenir de nombreux dépassements
de buffer, donc vous ne devriez pas le laisser en libre
accès à qui que ce soit.

Solution : Protégez l'accès à LinuxConf grace à un firewall,
ou si vous n'utilisez pas l'accès réseau, désactivez-le 
avec l'utilitaire linuxconf.

Pour plus d'informations sur les dangers de LinuxConf,
allez voir :
http://www.securiteam.com/exploits/Linuxconf_contains_remotely_exploitable_buffer_overflow.html

Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detect Linuxconf access rights";
 summary["francais"] = "Detecte si LinuxConf autorise son accès par le réseau";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes");
 script_require_ports("Services/linuxconf", 98);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/linuxconf");
if(!port)port = 98;
if (get_port_state(port))
{
 soctcp98 = open_sock_tcp(port);

 if (soctcp98)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp98, data:sendata);
  banner = http_recv(socket:soctcp98);
  http_close_socket(soctcp98);
  
  if ("Server: linuxconf" >< banner)
  {
    resultrecv = strstr(banner, "Server: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "Server: ";
    resultrecv = resultrecv - "\n";
   
    banner = string("Linuxconf version is : ");
    banner = banner + resultrecv;
    security_warning(port);
    security_warning(port:port, data:banner);
  }
 }
}
