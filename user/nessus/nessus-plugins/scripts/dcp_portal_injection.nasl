#
# written by Renaud Deraison
#
# DCP-Portal Cross Site Scripting Bugs
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: DCP-Portal (PHP)


if (description)
{
 script_id(11476);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(6525);
 
 script_name(english:"DCP-Portal Code Injection");
 desc["english"] = "
DCP-Portal v5.0.1  has a code injection bug. An attacker may use it to 
execute arbitrary PHP code on this host.

Solution : Upgrade to a newer version.
Risk factor : Serious";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if DCP-Portal is vulnerable to an injection attack");
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


dir = make_list(cgi_dirs(), "");
		


foreach d (dir)
{
 url = string(d, "/library/lib.php?root=http://xxxxxxxxxxx");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if("http://xxxxxxxxxxx/lib_nav.php" >< buf)
   {
    security_hole(port);
    exit(0);
   }
}

