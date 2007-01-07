#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
   script_id(11007);
   script_version ("$Revision: 1.4 $");
   name["english"] = "ActiveState Perl directory traversal";
   script_name(english:name["english"]);
 
   desc["english"] = "
It is possible to execute arbitrary commands on the remote
server by using ActiveState's perl.

Solution : Upgrade to the latest version

Reference : http://online.securityfocus.com/archive/1/149482

Risk factor : High";


   script_description(english:desc["english"]);
 
   summary["english"] = "Determines if ActivePerl is vulnerable";
   script_summary(english:summary["english"]);
 
   script_category(ACT_ATTACK);
 
   script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
   script_family(english:"CGI abuses");
   script_dependencie("find_service.nes", "http_version.nasl");
   script_require_ports("Services/www", 80);
   script_require_keys("www/iis");
   exit(0);
}


#
# The code starts here
# 

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);

quote = raw_string(0x22);

item = string("/.", quote, "./.", quote,  "./winnt/win.ini%20.pl");
req = http_get(item:item, port:port);

soc = http_open_socket(port);
if(!soc)exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
if("Semicolon seems to be missing at" >< r)
{
 security_hole(port);
}
