# This script was written by Renaud Deraison
#
# Ref :
#  Date: 1 Apr 2003 13:08:28 -0000
#  From: magistrat <magistrat@blocus-zone.com>
#  To: bugtraq@securityfocus.com
#  Subject: Css in Xoops module glossary 1.3.x

#
# This check will incidentally cover other flaws.

if(description)
{
 script_id(11508);
 script_bugtraq_id(7356);
 script_version ("$Revision: 1.4 $");

 
 name["english"] = "Xoops XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Xoops CGI suite.

There is a cross site scripting issue in this suite
which may allow an attacker to steal your users cookies.

The flaw lies in the cgi glossaire-aff.php.

You are advised to remove this CGI.

Solution : None at this time
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Xoops";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (make_list( "", cgi_dirs()))
{
 req = http_get(item:string(d, "/modules/glossaire/glossaire-aff.php?lettre=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&
    egrep(pattern:"<script>foo</script>", string:res)){
 	security_warning(port);
	exit(0);
 }
}
