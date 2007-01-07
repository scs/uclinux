#
# written by Renaud Deraison
#
# Date: Sun, 23 Mar 2003 16:13:37 -0500
# To: bugtraq Security List <bugtraq@securityfocus.com>
# From: flur <flur@flurnet.org>
# Subject: paFileDB 3.x SQL Injection Vulnerability

if (description)
{
 script_id(11478);
 script_bugtraq_id(7183);
 script_version ("$Revision: 1.3 $");

 
 script_name(english:"paFileDB SQL injection");
 desc["english"] = "
The remote pafiledb.php is vulnerable to a SQL injection attack.
An attacker may use this flaw to control your database.

Solution : None at this time
Risk factor : Serious";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if pafiledb is vulnerable to a SQL injection");
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
 url = string(d, "/pafiledb.php?action=rate&id=1&rate=dorate&ratin=`");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if("UPDATE pafiledb_files SET file_rating" >< buf)
   {
    security_hole(port);
    exit(0);
   }
}

