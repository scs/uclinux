#
# (C) Tenable Network Security

if (description)
{
 script_id(11753);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(7952);
 
 script_name(english:"SquirrelMail's Multiple Flaws");
 desc["english"] = "
The remote host is running SquirrelMail, a web-based mail server.

There is a flaw in the remote installation which may allow an
attacker with a valid webmail account to read, move and delete arbitrary 
files on this server, with the privileges of the HTTP server.

Solution : Upgrade to SquirrelMail 1.2.12 when it is available
Risk Factor : Serious";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if squirrelmail reads arbitrary files");
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
if (!port) port = 80;
if(!get_port_state(port))exit(0);


dir = make_list( cgi_dirs(), "/mail", "");
		

foreach d (dir)
{
 req = http_get(item:d + "/src/redirect.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 
 if(egrep(pattern:"SquirrelMail version (0\..*|1\.([0-1]\..*|2\.([0-9]|1[01])))[^0-9]", string:res))
 {
  security_warning(port);
  exit(0);
 }
}
