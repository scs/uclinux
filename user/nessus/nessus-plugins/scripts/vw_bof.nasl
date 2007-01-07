#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10650);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CAN-2001-0432");
 script_bugtraq_id(2579);
 
 
 
 name["english"] = "VirusWall's catinfo overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote cgi /catinfo seems to be vulnerable
to a buffer overflow when it receives a too long
input strings, allowing any user to execute arbitrary
commands as root.

This CGI usually comes with the VirusWall suite.
	   
Solution : if you are using VirusWall, upgrade to version 3.6, or
else you *may* ignore this warning	   
Risk factor : Serious";




 script_description(english:desc["english"]);
 
 summary["english"] = "Overflow in catinfo";
 summary["francais"] = "Overflow dans catinfo";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 1812);
 script_require_keys("www/cern");
 exit(0);
}

#
# The script code starts here
#


#
# We can not determine if the overflow actually took place or
# not (as it took place when the CGI attempts to exit), so 
# we check if the cgi dumbly spits a 2048 octets long name.
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 1812;
if(!get_port_state(port))exit(0);

ok = is_cgi_installed(item:"/catinfo", port:port);
if(!ok)exit(0);

if(safe_checks())
{
 req = http_get(item:string("/catinfo?", crap(128)), port:port);
soc = http_open_socket(port);
send(socket:soc, data:req);
code = recv_line(socket:soc, length:4096);
if("404" >< code)exit(0);
r = http_recv(socket:soc);
http_close_socket(socket:soc);
if(crap(128) >< r)
{
 report = "
The remote cgi /catinfo seems to be vulnerable
to a buffer overflow when it receives a too long
input strings, allowing any user to execute arbitrary
commands as root.

This CGI usually comes with the VirusWall suite.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.
	   
Solution : if you are using VirusWall, upgrade to version 3.6, or
else you *may* ignore this warning	   
Risk factor : Serious";
  security_hole(port:port, data:report);
 }
 exit(0);
}

req = http_get(item:string("/catinfo?", crap(2048)), port:port);
soc = http_open_socket(port);
send(socket:soc, data:req);
code = recv_line(socket:soc, length:4096);
if("404" >< code)exit(0);
r = http_recv(socket:soc);
http_close_socket(socket:soc);
if(crap(2048) >< r)
{
  security_hole(port);
}
