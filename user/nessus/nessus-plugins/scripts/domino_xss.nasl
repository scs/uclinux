#
# This script is (C) Renaud Deraison
#


if(description)
{
 script_id(11394);
 script_version ("$Revision: 1.5 $");
 
 script_bugtraq_id(2962);
 script_cve_id("CVE-2001-1161");

 name["english"] = "Lotus Domino XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is vulnerable to cross-site scripting,
when requesting a .nsf file with html arguments, as in :

GET /home.nsf/<img%20src=javascript:alert(document.domain)>


Solution : Upgrade to Domino 5.0.8 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Lotus Domino XSS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl", "domino_default_db.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

list = get_kb_list(string("www/domino/", port, "/db"));
if(!isnull(list))
{
 file = list[0];
}
else {
	list = get_kb_list(string("www/", port, "/content/extensions/nsf"));
	if(!isnull(list))file = list[0];
	else file = "/home.nsf"; # Maybe we'd better exit now.
}
	
	
req = http_get(item:string(file,"/<img%20src=javascript:alert(document.domain)>"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

if ( res == NULL ) exit (0);

if("<img src=javascript:alert(document.domain)>" >< res ) security_warning(port);
