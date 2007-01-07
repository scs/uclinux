#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11722);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CAN-2001-1150");
 script_bugtraq_id(3216);
 
 
 name["english"] = "cgiWebupdate.exe vulnerability";
 name["francais"] = "cgiWebupdate.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The CGI 'cgiWebupdate.exe' exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

An attacker can use this hole to gain access to confidential data
or escalate their privileges on the web server.

Solution : remove it from the cgi-bin or scripts folder.

*** As Nessus solely relied on the existence of the cgiWebupdate.exe file, 
*** this might be a false positive


Risk factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the cgiWebupdate.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/cgiWebupdate.exe"), port:port)) {
  	security_hole(port);
	exit(0);
	}
   } 
