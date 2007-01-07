# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

if(description)
{
 script_id(11028);
 script_cve_id("CVE-2002-0364", "CAN-2002-0071", "CAN-2002-0364");
 script_bugtraq_id(4855);
 script_version ("$Revision: 1.7 $");
 name["english"] = "IIS .HTR overflow";
 name["francais"] = "IIS .HTR ISAPI overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is vulnerable to a buffer overflow in the .HTR
filter.

An attacker may use this flaw to execute arbitrary code on
this host (although the exploitation of this flaw is considered
as being difficult).

Solution: 
To unmap the .HTR extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .htr from the list.

See MS bulletin MS02-028 for a patch

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for IIS .htr ISAPI filter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}
include("http_func.inc");

req = string("POST /NULL.htr HTTP/1.1\r\n",
 "Host: ", get_host_name(), "\r\n",
 "Transfer-Encoding: chunked\r\n\r\n",
 "20\r\n",
 crap(32), "\r\n",
 "0\r\n\r\n");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
soc = http_open_socket(port);
if(soc)
{
  send(socket:soc, data:req);
  r = http_recv_headers(soc);
  if(egrep(string:r, 
	   pattern:"^HTTP/1.[01] 100 Continue")
    )
  {
  r2 = http_recv_body(socket:soc, length:0, headers:r);
  if(!r2)security_hole(port);
  }
  http_close_socket(soc);
}
