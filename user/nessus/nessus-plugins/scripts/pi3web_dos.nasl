#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
#
# See the Nessus Scripts License for details
#
# We do banner checking, as I could not get my hands on a vulnerable version
#
# Refs: http://online.securityfocus.com/archive/1/250126
#

if(description)
{
 script_id(11099);
 script_cve_id("CAN-2002-0142");
 script_bugtraq_id(3866);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Pi3Web Webserver v2.0 Buffer Overflow ";

 script_name(english:name["english"]);

 desc["english"] = "
The remote server may crash when it is sent 
a very long cgi paramater multiple times, as in :

	GET /cgi-bin/hello.exe?AAAAA[...]AAAA
	
An attacker may use this flaw to prevent the remote
host from working properly.

Solution: upgrade to version 2.0.1 of Pi3Web
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a DoS in Pi3Web";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_GATHER_INFO);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl");

 # Family
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");

 script_require_ports("Services/www", 80);
 exit(0);
}


include ("http_func.inc");
port = get_kb_item("Services/www");
if(!port) port = 80;


banner = get_http_banner(port:port);
if(banner)
{
 if(egrep(pattern:"^Server: Pi3Web/2\.0\.[01]", string:banner))
       security_hole(port);
}

