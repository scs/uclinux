#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10181);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(2653);
 script_cve_id("CAN-2000-0074");
 name["english"] = "PlusMail vulnerability";
 name["francais"] = "PlusMail vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'plusmail' CGI is installed. Some
versions of this CGI have a well known security flaw that 
lets an attacker read arbitrary
file with the privileges of the http daemon 
(usually root or nobody).

Solution : remove it from /cgi-bin. No patch yet

Risk factor : Serious";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/plusmail";
 summary["francais"] = "Vérifie la présence de /cgi-bin/plusmail";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

port = is_cgi_installed("plusmail");
if(port)security_hole(port);
