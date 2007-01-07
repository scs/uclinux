#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# This script does not check for the flaw (lame). I hope I'll find details
# on it somehow.
#

if(description)
{
 script_id(11311);
 script_version ("$Revision: 1.2 $");
 
 script_bugtraq_id(5804);
 script_cve_id("CAN-2002-0692");
 name["english"] = "shtml.exe overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "

The remote host has FrontPage Server Extensions (FPSE) installed.

There is a denial of service / buffer overflow condition
in the program 'shtml.exe' which comes with it. However, 
no public detail has been given regarding this issue yet,
so it's not possible to remotely determine if you are
vulnerable to this flaw or not.

If you are, an attacker may use it to crash your web server
(FPSE 2000) or execute arbitrary code (FPSE 2002). Please
see the Microsoft Security Bulletin MS02-053 to determine
if you are vulnerable or not.


*** Nessus did not actually check for this flaw, so this
*** might be a false positive


Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-053.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of shtml.exe";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(get_port_state(port))
{
  req = http_get(item:"/_vti_bin/shtml.exe",
  		 port:port);
		 
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL )exit(0);
  
  if("Smart HTML" >< res)security_hole(port);
}

