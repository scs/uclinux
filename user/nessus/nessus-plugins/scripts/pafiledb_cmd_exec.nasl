#
# (C) Tenable Network Security
#
# Ref:
# Date: Thu, 24 Jul 2003 08:52:33 +0200
# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: paFileDB 3.1
#


if (description)
{
 script_id(11806);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(8271);
 
 script_name(english:"paFileDB command execution");
 desc["english"] = "
The remote host is hosting a version of the file pafiledb.php which is
older than version 3.2. There is a bug in this version which may allow
anyone upload arbitrary files on this host, and even execute arbitrary
commands.
  
Solution : Upgrade to paFileDB 3.2
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine the version of pafiledb");
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


dir = make_list( cgi_dirs(), "");
		
foreach d (dir)
{
 url = string(d, '/pafiledb.php');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))exit(0);

 if(egrep(pattern:"<!--Download database powered by paFileDB ([0-2]\..*|3\.[01][^0-9])", string:buf))
   {
    security_warning(port);
    exit(0);
   }
}

