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
 script_id(11044);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(5189);
 
 name["english"] = "ICECast FileSystem disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server does not return the same error codes when it is requested
a non-existent directory and an existing one. An attacker may use this flaw
to deduct the presence of several key directory on the remote server, and
therefore gain further knowledge about it.

Risk factor : Low
Solution : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the error code is the same when requesting inexisting and existing dirs";
 
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#



include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 8000;

if(!get_port_state(port))exit(0);

req1 = http_get(port:port, item:"/test/../../../../../../../../../inexistant_i_hope/");
req2 = http_get(port:port, item:"/test/../../../../../../../../../etc/");

soc1 = http_open_socket(port);
if(!soc1)exit(0);
send(socket:soc1, data:req1);
r1 = recv_line(socket:soc1, length:13);
http_close_socket(soc1);

soc2 = http_open_socket(port);
if(!soc2)exit(0);
send(socket:soc2, data:req2);
r2 = recv_line(socket:soc2, length:13);
http_close_socket(soc2);

if(!(r2 == r1))security_warning(port);

