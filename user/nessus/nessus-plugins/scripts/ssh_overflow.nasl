#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10269);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(843);
 script_cve_id("CVE-1999-0834");
 
 name["english"] = "SSH Overflow";
 name["francais"] = "Buffer overflow dans SSH";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of SSH which is 
older than (or as old as) version 1.2.27.
If this version was compiled against the
RSAREF library, then it is very likely to
be vulnerable to a buffer overflow which
may be exploited by an attacker to gain
root on your system.

To determine if you compiled ssh against
the RSAREF library, type 'ssh -V' on the
remote host.

Risk factor : High
Solution : Use ssh 2.x, or do not compile ssh
against the RSAREF library";

	
 desc["francais"] = "
Vous faites tourner une version de ssh
plus ancienne ou égale à la version 1.2.27.

Cette version est vulnérable à un dépassement
de buffer dans le cas où elle serait compilée
avec la bibliothèque RSAREF, ce qui permettrait
à un pirate de passer root sur ce système.

Pour déterminer si vous avez compilé SSH avec
RSAREF, tappez 'ssh -V' sur le système distant.

Facteur de risque : Elevé
Solution : utilisez ssh 2.x, ou recompilez ssh en
désactivant le support rsaref.";


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
 script_dependencie("find_service.nes");
 script_require_ports("Services/ssh", 22);
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
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(22);
 if(!soc)exit(0);
 banner = recv_line(socket:soc, length:4096);
 close(soc);
}

if(ereg(string:banner,
  	pattern:"SSH-.*-1\.([0-1]|2\.([0-1]..*|2[0-7]))[^0-9]*$", icase:TRUE))security_warning(port);
