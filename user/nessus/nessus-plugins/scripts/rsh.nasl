#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10245);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CAN-1999-0651");

 name["english"] = "rsh";
 name["francais"] = "rsh";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The rsh service is running.
This service is dangerous in the sense that
it is not ciphered - that is, everyone can sniff
the data that passes between the rsh client
and the rsh server. This includes logins
and passwords.

You should disable this service and use ssh instead.

Solution : Comment out the 'rsh' line in /etc/inetd.conf.

Risk factor : Low";


 desc["francais"] = "Le service rsh tourne.
Ce service est dangereux dans le sens où la communication
entre le serveur et le client n'est pas chiffrée, 
ce qui permet à n'importe qui de sniffer les données
qui passent entre le client et le serveur - ce qui
inclut les noms d'utilisateurs et leur mot de passe.

Vous devriez désactiver ce service et utiliser
ssh à la place.

Solution : désactivez ce service dans /etc/inetd.conf.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of rsh";
 summary["francais"] = "Vérifie la présence du service rsh";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rsh", 514);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = get_kb_item("Services/rsh");
if(!port)port = 514;

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = "root" + raw_string(0) + "root" + raw_string(0) + "xterm/38400" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024);
  if(strlen(a)){
	set_kb_item(name:"rsh/active", value:TRUE);
    register_service(port: port, proto: "rsh");
    security_warning(port);
  }
  else {
    a = recv(socket:soc, length:1024);
    if(strlen(a))
    {
     set_kb_item(name:"rsh/active", value:TRUE);
     security_warning(port);
     register_service(port: port, proto: "rsh");
    }
  }
  close(soc);
 }
}
