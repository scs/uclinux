# This script is (C) Noam Rathaus
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID,  deleted link as it is provided in Bugtraq exploits section


if (description)
{
 script_id(10779);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(6141);
 script_name(english:"CGIEmail's CGICso (Send CSO via CGI) Command Execution Vulnerability");
 desc["english"] = "
The remote host seems to be vulnerable to a security problem in 
CGIEmail (cgicso).  The vulnerability is caused by inadequate processing 
of queries by CGIEmail's cgicso and results in a command execution 
vulnerability.

Impact:
The server can be compromised by executing commands as the web server's 
running user (usually 'nobody').

Solution:
Modify cgicso.h to contain a strict setting of your finger host.

Example:
Define the following in cgicso.h:
#define CGI_CSO_HARDCODE
#define CGI_CSO_FINGERHOST 'localhost'

Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the cgicso vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 SecurITeam");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;
if (!get_port_state(port))exit(0);

dir = cgi_dirs();


for (i = 0; dir[i] ; i = i + 1)
{
 data = string(dir[i], "/cgicso?query=AAA");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if ("400 Required field missing: fingerhost" >< buf)
   {
    security_hole(port:port);
    exit(0);
   }
}
