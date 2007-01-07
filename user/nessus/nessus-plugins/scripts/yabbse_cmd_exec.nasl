#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11588);
 script_bugtraq_id(7399, 6674, 6663, 6591, 1921);
 script_cve_id("CAN-2000-1176");
 script_version ("$Revision: 1.3 $");

 script_name(english:"YaBB SE command execution");
 desc["english"] = "
The remote host is using the YaBB SE forum management system.

According to its version number, this forum is vulnerable to a
code injection bug which may allow an attacker with a valid account
to execute arbitrary commands on this host by sending a malformed
'language' parameter in the web request.

In addition to this flaw, this version is vulnerable to other flaws
such as SQL injection.

Solution: Upgrade to YaBB SE 1.5.2 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if YaBB SE can be used to execute arbitrary commands");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;



if(!get_port_state(port))exit(0);


dirs = make_list("/yabbse", cgi_dirs(), "", "/forum");
		

foreach d (dirs)
{
 url = string(d, "/index.php?board=nonexistant", rand());
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:".*Powered by.*YaBB SE (0\.|1\.([0-4]\.|5\.[01])).*YaBB", string:buf))
   {
    security_hole(port);
    exit(0);
   }
}
