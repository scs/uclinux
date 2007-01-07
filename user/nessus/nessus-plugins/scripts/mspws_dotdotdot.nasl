#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10142);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0386");
 name["english"] = "MS Personal WebServer ...";
 name["francais"] = "MS Personal WebServer ...";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to read
any file on the remote system by prepending
several dots before the file name.

Example :

	GET ........../config.sys

Solution : Disable this service and install
a real Web Server.

Risk factor : High";	

 desc["francais"] = "Il est possible de lire
n'importe quel fichier sur la machine distante
en ajoutant des points devant leur noms.
Nous avons essayé de faire :

	GET ......./config.sys
	
Solution : désactivez ce service et installez
un vrai serveur web.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "......../file.txt";
 summary["francais"] = "......./file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


cgi = "/................../config.sys";
port = is_cgi_installed(cgi);
if(port)security_hole(port);

 
