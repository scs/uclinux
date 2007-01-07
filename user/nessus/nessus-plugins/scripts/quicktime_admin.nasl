#
# This script was written by Michael Scheidell SECNAP Network Security
#
# based on @stake advisory
# http://www.atstake.com/research/advisories/2003/a022403-1.txt
# 
# See the Nessus Scripts License for details
#
# any patches to exploit hole appreciated and credit given
# this could actually be split into 5 ;-) with different families
# remote butter, remote command, XSS, etc.

if(description)
{
 script_id(11278);
 script_version("$Revision: 1.5 $");
 
 script_cve_id("CAN-2003-0050","CAN-2003-0051","CAN-2003-0052","CAN-2003-0053","CAN-2003-0054","CAN-2003-0055");
 script_bugtraq_id(6954, 6955, 6956, 6957, 6958, 6960, 6990);
 
 name["english"] = "Quicktime/Darwin Remote Admin Exploit";
 script_name(english:name["english"]);
 
 desc["english"] = "
Cross site scripting, buffer overflow and remote command
execution on QuickTime/Darwin Streaming Administration
Server.

This is due to parsing problems with per script:
parse_xml.cgi.

The worst of these vulnerabilities allows for remote
command execution usually as root or administrator.

These servers are installed by default on port 1220.

See:
http://www.atstake.com/research/advisories/2003/a022403-1.txt

Solution:  Obtain a patch or new software from Apple or
block this port (TCP 1220) from internet access.

*** Nessus reports this vulnerability using only
*** information that was gathered. Only the existance
*** of the potentially vulnerable cgi script was tested.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Quicktime/Darwin server for parse_xml.cgi";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Michael Scheidell");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl","no404.nasl");
 script_require_ports("Services/www", 1220);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:1220);
cgi = "parse_xml.cgi";

foreach port (ports)
{
 foreach dir (make_list("", "/AdminHTML", cgi_dirs()))
 {
  if(is_cgi_installed_ka(item:string(dir, "/", cgi), port:port))
	{
	 security_hole(port);
	 break;
	}
 }
}
