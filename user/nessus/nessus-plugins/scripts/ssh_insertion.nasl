#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10268);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1085");
 
 name["english"] = "SSH Insertion Attack";
 name["francais"] = "Attaque contre SSH par insertion";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of SSH which is 
older than (or as old as) version 1.2.23.
This version is vulnerable to a known plain 
text attack, which may allow an attacker to 
insert encrypted packets in the client - server 
stream that will be deciphered by the server, 
thus allowing the attacker to execute arbitrary
commands on the remote server

Solution :
Upgrade to version 1.2.25 of SSH which solves this problem.

More information:
http://www.core-sdi.com/english/ssh/

Risk factor : High";
	
	
 desc["francais"] = "
Vous faites tourner une version de ssh
plus ancienne ou égale à la version 1.2.23.

Cette version est vulnérable à une 'known
plaintext attack' qui peut permettre à un
pirate d'insérer des paquets chiffrés dans
le flux ssh qui seront déchiffrés du coté
du serveur, permettant ainsi au pirate 
d'executer des commandes arbitraires 
sur la machine distante.

Solution :
	mettez à jour ssh. La version 1.2.25
et les versions ultérieures corrigent ce problème.


Plus d'informations :
	http://www.core-sdi.com/english/ssh/
	
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_exclude_keys("ssh/openssh");
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;

key = string("ssh/banner/", port);
banner = get_kb_item(key);


if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(!soc)exit(0);
    banner = recv_line(socket:soc, length:1024);
    close(soc);
  }
}

if(!banner)exit(0);
banner = tolower(banner);

b = banner - string("\r\n");

if("openssh" >< b)exit(0);

if(ereg(pattern:"ssh-.*-1\.2(\.([0-9]|1[0-9]|2[0123])|)$", string:b))
	security_warning(port);
