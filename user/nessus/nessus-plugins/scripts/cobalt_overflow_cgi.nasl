#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# GPL
#
# References: http://www.securiteam.com/exploits/6S0022A6AA.html
#

if(description)
{
 script_id(11190);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "overflow.cgi detection";
 script_name(english:name["english"]);
 
 desc["english"] = "/cgi-bin/.cobalt/overflow/overflow.cgi was detected.
Some versions of this CGI allow remote users to execute arbitrary commands
with the privileges of the web server.

*** Nessus just checked the presence of this file 
*** but did not try to exploit the flaw, so this might
*** be a false positive
   
See: http://www.cert.org/advisories/CA-2002-35.html

Solution : get a newer software from Cobalt
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a CGI";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 81, 444);
 exit(0);
}

#

port = is_cgi_installed("/cgi-bin/.cobalt/overflow/overflow.cgi");
if(port) security_hole(port);
