#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10423);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(1133);
 script_cve_id("CVE-2000-0320");
 
 name["english"] = "qpopper euidl problem";
 name["francais"] = "qpopper euild";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
You are using qpopper 2.53 (or newer in the
2.5x series)

There is a problem in this server which allows
users who have a pop account to gain a shell 
with the gid 'mail' by sending to themselves a 
specially crafted mail.


Solution : Upgrade to the latest qpopper software
Risk factor : Medium";

 desc["francais"] = "
Vous utilisez qpopper 2.53 (ou plus récent dans la série
des 2.5x)

Il y a un problème avec ce serveur POP qui permet
à un utilisateur ayant un compte pop valide d'obtenir
un shell avec le gid 'mail' en s'envoyant un message
spécialement formé.

Solution : mettez votre serveur à jour en 3.0.2
Facteur de risque : Moyen";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "checks for the version of qpopper";
 summary["francais"] = "vérifie la version de qpopper";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes");
		       		     
 script_require_ports("Services/pop3", 110);
 exit(0);
}


port = get_kb_item("Services/pop3");
if(!port)port = 110;

if(get_port_state(port))
{

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 close(soc);	
 if(ereg(pattern:"^\+OK QPOP \(version (2\.((5[3-9]+)|([6-9][0-9]+))\)|3\.0).*$",
 	 string:b))
	  security_hole(port);
	  
}

