#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
# modded by John Jackson <jjackson@attrition.org> to pull hostname
#
# changes by rd : more verbose report on hostname
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10006);
 script_version ("$Revision: 1.17 $");
 name["english"] = "PC Anywhere";
 name["francais"] = "PC Anywhere";
 script_name(english:name["english"], francais:name["francais"]);

 
 desc["english"] = "PC Anywhere is running.

 This service could be used by an attacker to partially take the control
 of the remote system.

 An attacker may also use it to steal your password or prevent your system
 from working properly.

 Solution : Disable this service if you do not use it.

 Risk factor : Medium";

  desc["francais"] = "PC Anywhere est activé.

  Ce service peut être utilisé par des pirates pour prendre le 
  controle de la machine distante.

  Un pirate peut l'utiliser pour voler vos mots de passes ou
  vous empecher de travailler convenablement.

  Solution : Désactivez ce service si vous ne l'utilisez pas

  Facteur de risque : Moyen";

  script_description(english:desc["english"], francais:desc["francais"]);


   summary["english"] = "Checks for the presence PC Anywhere";
   summary["francais"] = "Vérifie la présence de PC Anywhere";
   script_summary(english:summary["english"], francais:summary["francais"]);


 script_category(ACT_GATHER_INFO);

script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin",
               francais:"Ce script est Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");


exit(0);
}


#
# The script code starts here
#

function probe(port1, port2)
{
  udpsock = open_sock_udp(port1);
  udpsock2 = open_sock_udp(port2);
  
  data = string("NQ");
  data2 = string("ST");

  send(socket:udpsock, data:data);
  send(socket:udpsock, data:data2);
  send(socket:udpsock2, data:data);
  send(socket:udpsock2, data:data2);
  
  z = recv(socket:udpsock, length:1024, min:1);
  if(z)
  {
    security_warning(port:port1, protocol:"udp");
    exit(0);
  }
  else
  {
    z = recv(socket:udpsock2, length:1024, min:1, timeout:1);
    if(z)
     {
       security_warning(port:port2, protocol:"udp");
       exit(0);
     }
   }
       
  close(udpsock);
  close(udpsock2);
}

if(get_udp_port_state(22) || get_udp_port_state(5632))
 probe(port1:22, port2:5632);

