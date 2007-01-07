#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11587);
 script_bugtraq_id(7406);
 script_version ("$Revision: 1.3 $");

 script_name(english:"XMB SQL Injection");
 desc["english"] = "
The remote host is using XMB Forum.

According to its version number, this forum is vulnerable to a
SQL injection bug which may allow an attacker to steal the
passwords hashes of any user of this forum, including the forum
administrator.

Once he has the password hashes, he can easily setup a brute-force
attack to crack the users passwords and then impersonate them. If the
administrator password is obtained, an attacker may even edit the
content of this website.

Solution: Upgrade to XMB Forum 1.8 SP1 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if XMB forums is vulnerable to a sql injection attack");
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


dir = make_list(cgi_dirs(), "", "/forum");
		


foreach d (dir)
{
 url = string(d, "/");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    egrep(pattern:"Powered by XMB (0\.|1\.[0-7])", string:buf))
   {
    security_warning(port);
    exit(0);
   }
   
   str = egrep(pattern:"Powered by XMB 1\.8", string:buf);
   if(str)
   {
    if("SP1" >!< str)security_warning(port);
   }
}
