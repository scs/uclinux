#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10472);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(1426);
 script_cve_id("CVE-2000-0575");
 
 name["english"] = "SSH Kerberos issue";
 name["francais"] = "SSH et Kerberos";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of SSH which is 
older than (or as old as) version 1.2.27.

If you compiled ssh with kerberos support,
then an attacker may eavesdrop your users
kerberos tickets, as sshd will set
the environment variable KRB5CCNAME to
'none', so kerberos tickets will be stored
in the current working directory of the
user, as 'none'.

If you have nfs/smb shared disks, then an attacker
may eavesdrop the kerberos tickets of your
users using this flaw.

*** If you are not using kerberos, then
*** ignore this warning.

Risk factor : Serious
Solution : use ssh 1.2.28 or newer";

	
 desc["francais"] = "
Vous faites tourner une version de ssh
plus ancienne ou égale à la version 1.2.27.

Si celle-ci a été compilé avec le support
kerberos, alors un pirate peut éventuellement
sniffer les tickets kerberos de vos utilisateurs,
puisque sshd met la variable d'environement
KRB5CCNAME à 'none', ce qui a pour conséquence
le fait que les tickets kerberos seront stockés
dans le répertoire courant, dans le fichier none.

Si vous partagez des disques par NFS/SMB, alors
un pirate peut écouter les données qui passe et
obtenir les tickets kerberos de vos utilisateurs
en utilisant ce problème.

*** Si vous n'utilisez pas kerberos, ignorez ce message

Facteur de risque : Serieux
Solution : utilisez ssh 1.2.28";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;
if(!get_port_state(port))exit(0);

key = string("ssh/banner/", port);
banner = get_kb_item(key);


if(!banner){
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:1024);
	close(soc);
	}

if(ereg(string:tolower(banner),
  	pattern:"ssh-.*-1\.([0-1]\..*|2\.([0-1]..*|2[0-7]))[^0-9]*"))security_warning(port);
