#
# This script was written by Tor Houghton, but I looked at "htdig" by 
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Changes by rd:
# - phrasing in the report
# - pattern read
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10847);
 script_version ("$Revision: 1.5 $");

 name["english"] = "SilverStream database structure";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to download the remote SilverStream database
structure by requesting :
	http://www.example.com/SilverStream/Meta/Tables/?access-mode=text
	
	
An attacker may use this flaw to gain more knowledge about
this host.

Reference : http://online.securityfocus.com/archive/101/144786

Risk factor : Medium
Solution : Reconfigure the server so that others
cannot view database structure";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if SilverStream database structure is visible.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Tor Houghton");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
  script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(get_port_state(port)) {
   soc = http_open_socket(port);
   if(soc) {
      buf = string("/SilverStream/Meta/Tables/?access-mode=text");
      buf = http_get(item:buf, port:port);
      send(socket:soc,data:buf);
      rep = http_recv(socket:soc);
      if("_DBProduct" >< rep)
         security_warning(port);
      http_close_socket(soc);
   }
}

