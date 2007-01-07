#
# This script is (C) Tenable Network Security
#




if(description)
{
 script_id(11752);
 script_bugtraq_id(7954);
 script_version ("$Revision: 1.1 $");

 name["english"] = "Proxomitron DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Proxomitron proxy. There might be a bug
in this software which may allow an attacker to disable it remotely.

*** Nessus did not check for the presence of the flaw, so this might
*** be a false positive.


Solution : Disable this service
Risk Factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of proxomitron";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 8080;
if(!get_port_state(port))exit(0);


if ( 1 || safe_checks() )
{
 req = http_get(item:"/", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if( "<title>The Proxomitron Reveals...</title>" >< res )
 {
  security_hole(port:port, data:report);
  exit(0);
 }
}

#
# the following makes proxomitron close the connection abruptely, 
# however it's false positive prone so it's disabled.
#

req = http_get(item:crap(data:"/../..0%%../", length:5000), port:port);
soc = http_open_socket(port);
if( !soc ) exit(0);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);
