#
# (C) Tenable Network Security
#


if (description)
{
 script_id(11744);
 script_bugtraq_id(7697);

 script_name(english:"Post-Nuke SQL injection");
 desc["english"] = "
The remote host is running a version of Post-Nuke which is vulnerable
to a SQL injection attack.

An attacker may use this flaw to gain the control of the database
of this host.

Solution : Upgrade to the latest version of postnuke
Risk factor : Serious";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if post-nuke is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

foreach dir (make_list("", "/post-nuke", "/pn", cgi_dirs()))
{
 req = http_get(item:string(dir, "/modules.php?op=modload&name=Glossary&file=index&page='"),
 		port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL ) exit(0);
 
 if( "hits=hits+1 WHERE" >< res )
 {
    	security_hole(port);
	exit(0);
 }
}
