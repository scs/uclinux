#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# based on php3_path_disclosure by Matt Moore
#
#
# See the Nessus Scripts License for details
#
# References
# From: "Peter_Grundl" <pgrundl@kpmg.dk>
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002006: Lotus Domino Physical Path Revealed
# Date: Tue, 2 Apr 2002 16:18:06 +0200
#

if(description)
{
 script_id(11009);
 script_cve_id("CAN-2002-0245");
 script_bugtraq_id(4049);
 script_version ("$Revision: 1.7 $");
 name["english"] = "Lotus Domino Banner Information Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to obtain the physical path to the remote web root
by requesting a non-existent .pl file.

Solution : Upgrade to Dominor 5.0.10 if you're using it, or contact
your vendor for a patch
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Lotus Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 file = string("/cgi-bin/com5.pl");
 req = http_get(item:file, port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096);
 #display(r);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 50[0-9] .*", string:r))
 {
 r = http_recv(socket:soc);
 if(egrep(pattern:"[A-Z]:.*com5\.pl", string:r, icase:TRUE))
   	security_warning(port);
 }
 http_close_socket(soc);
 }
}
