# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# It was modified by H D Moore to not crash the server during the test
#
#
# Supercedes MS01-033
#
#
# 
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10685);
 script_cve_id( "CVE-2001-0544", 
 		"CVE-2001-0545", 
		"CVE-2001-0506", 
		"CVE-2001-0507", 
		"CVE-2001-0508",
		"CVE-2001-0500");
 script_bugtraq_id(2690, 3190, 3194, 3195);
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "IIS ISAPI Overflow";

 script_name(english:name["english"]);

 desc["english"] = "
There's a buffer overflow in the remote web server through
the ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user SYSTEM.

Solution: See http://www.microsoft.com/technet/security/bulletin/ms01-044.asp
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a remote buffer overflow in IIS";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_ATTACK);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl");

 # Family
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");

 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

# The attack starts here
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port)) {
   
     
    soc = http_open_socket(port);
    if(!soc)exit(0);
    
    req = string("GET /x.ida?", crap(length:220, data:"x"), "=x HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n\r\n");

    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    # 0xc0000005 == "Access Violation"
    if ("0xc0000005" >< r)
    {
        security_hole(port);
    }
}
