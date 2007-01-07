#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11527);
 script_bugtraq_id(4944, 8013);
 script_cve_id("CAN-2002-0316", "CAN-2003-0375");
 script_version ("$Revision: 1.6 $");

 script_name(english:"XMB Cross Site Scripting");
 desc["english"] = "
The remote host is using XMB Forum.

This set of CGI is vulnerable to a cross-site-scripting issue
that may allow attackers to steal the cookies of your
users.

Solution: Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if XMB forums is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list(cgi_dirs(), "");
		


foreach d (dir)
{
 url = string(d, '/forumdisplay.php?fid=21"><script>x</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>x</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }

 url = string(d, '/buddy.php?action=<script>x</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>x</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }
 url = string(d, '/admin.php?action=viewpro&member=admin<script>x</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>x</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}
