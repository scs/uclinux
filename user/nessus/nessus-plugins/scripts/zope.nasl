#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10447);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(1354);
 script_cve_id("CVE-2000-0483");
 
 name["english"] = "Zope DocumentTemplate package problem";
 name["francais"] = "Problème dans le package DocumentTemplate de Zope";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server is Zope < 2.1.7

There is a security problem in all releases
prior to version 2.1.7 which can allow the
contents of DTMLDocuments or DTMLMethods
to be changed without forcing proper user
authentication.

Solution : Upgrade to Zope 2.1.7
Risk factor : Serious";




 desc["francais"] = "
Le serveur web distant est Zope < 2.1.7

Il y a un problème de sécurité affectant toutes
les releases de Zope inférieures à la version 2.1.7
qui permet de changer le contenu de DTMLDocuments
or DMTLMethods sans forcer l'utilisateur a se logguer
correctement.

Solution : Mettez Zope à jour en version 2.1.7
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for Zope";
 summary["francais"] = "Vérifie la présence de Zope";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
  
if(banner)
{ 
if(egrep(pattern:"^Server: .*Zope 2\.((0\..*)|(1\.[0-6]))", string:banner))
     security_hole(port);
}
