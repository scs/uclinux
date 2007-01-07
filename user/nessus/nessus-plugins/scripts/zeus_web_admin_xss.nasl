#
# This script was written by Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: 29 May 2003 17:48:30 -0000
#  From: Hugo "Vázquez" "Caramés" <overclocking_a_la_abuela@hotmail.com>
#  To: bugtraq@securityfocus.com
#  Subject: Another ZEUS  Server web admin XSS!


if(description)
{
 script_id(11681);
 script_bugtraq_id(7751);
 script_version ("$Revision: 1.3 $");

 
 name["english"] = "Zeus Admin Interface XSS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running the Zeus WebServer.

There is a vulnerability in the CGI vs_diag.cgi which may allow
an attacker to gain administrative access on that server. To
exploit this flaw, the attacker would need to lure the administrator
of this server to click on a rogue link.

Solution : Upgrade to the latest version of Zeus
Risk Factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for XSS in Zeus";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 9090);
 script_require_keys("www/zeus");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:9090);
foreach port (ports)
{
 if ( ! get_kb_item(string("www/", port, "/generic_xss")) ) 
 {
 req = http_get(item:"/apps/web/vs_diag.cgi?server=<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res != NULL )
  {
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<script>foo</script>" >< res) { security_warning(port); }
  }
 }
}

