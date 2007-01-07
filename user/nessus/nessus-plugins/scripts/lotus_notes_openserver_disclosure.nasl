#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
# Solution by David Litchfield (david@nextgenss.com)
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10795); 
 script_version ("$Revision: 1.7 $");

 name["english"] = "Lotus Notes ?OpenServer Information Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
A default behavior of Lotus Notes allows remote users to enumerate existing databases on a remote Domino (Lotus Notes) server. This information is considered sensitive, since it might reveal versions, logs, statistics, etc.

Solution: To disable this behavior open names.nsf and edit the Servers document in the Server view. From the Internet Protocols tab set 'Allow HTTP Clients to browse databases' to No.
This command doesn't affect a single database - it is a server-wide issue.

Risk factor : Medium

Additional information:
http://www.securiteam.com/securitynews/6W0030U35W.html
http://online.securityfocus.com/archive/1/223810
";

 script_description(english:desc["english"]);

 summary["english"] = "Lotus Notes ?OpenServer Information Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;

if(!get_port_state(port))exit(0);

req = http_get(item:"/?OpenServer", port:port);
soc = http_open_socket(port);
if (soc)
{
 send(socket:soc, data:req);
 buf = http_recv(socket:soc);
 http_close_socket(soc);
 #display(buf);
    
 if ((egrep(pattern:"!-- Lotus-Domino", string:buf)) && (egrep(pattern:"/icons/abook.gif", string:buf)))
 {
  security_hole(port:port);
  exit(0);
 }
}
