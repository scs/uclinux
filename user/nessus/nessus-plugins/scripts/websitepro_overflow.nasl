#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10476);
 script_cve_id("CAN-2000-0623");
 script_bugtraq_id(1492);
 script_version ("$Revision: 1.13 $");
 
 
 name["english"] = "WebsitePro buffer overflow";
 name["francais"] = "Website Pro buffer overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server is WebSitePro < 2.5

There are buffer overflow vulnerabilities
in all releases prior to version 2.5 of
this server.

Solution : Upgrade to WebSitePro 2.5 or newer
Risk factor : Serious";




 desc["francais"] = "
Le serveur web distant est WebSitePro < 2.5

Il y a des dépassements de buffers dans toutes
les releases antérieures à la version 2.5 de
ce serveur.

Solution : Mettez WebSitePro à jour en version 2.5 ou plus récent
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for WebSitePro";
 summary["francais"] = "Vérifie la présence de WebSitePro";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/websitepro");
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
  if(egrep(pattern:"Server: WebSitePro/2\.[0-4].*", string:banner))
     security_hole(port);
}

