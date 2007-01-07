#
# This script was written by Thomas Reinke <reinke@securityspace.com>
# Improvements re TRACK and RFP reference courtesy of <sullo@cirt.net>
# Improvements by rd - http_get() to get full HTTP/1.1 support, 
# security_warning() instead of security_hole(), slight re-phrasing
# of the description
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11213);
 script_version ("$Revision: 1.8 $");
 name["english"] = "http TRACE XSS attack";
 script_name(english:name["english"]);
 
 desc["english"] = '
Your webserver supports the TRACE and/or TRACK methods. TRACE and TRACK
are HTTP methods which are used to debug web server connections.   

It has been shown that servers supporting this method are subject
to cross-site-scripting attacks, dubbed XST for
"Cross-Site-Tracing", when used in conjunction with
various weaknesses in browsers.

An attacker may use this flaw to trick your
legitimate web users to give him their 
credentials.

Solution: Disable these methods.


If you are using Apache, add the following lines for each virtual
host in your configuration file :

    RewriteEngine on
    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
    RewriteRule .* - [F]

If you are using Microsoft IIS, use the URLScan tool to deny HTTP TRACE
requests or to permit only the methods needed to meet site requirements
and policy.

If you are using Sun ONE Web Server releases 6.0 SP2 and later, add the
following to the default object section in obj.conf:
    <Client method="TRACE">
     AuthTrans fn="set-variable"
     remove-headers="transfer-encoding"
     set-headers="content-length: -1"
     error="501"
    </Client>

If you are using Sun ONE Web Server releases 6.0 SP2 or below, compile
the NSAPI plugin located at:
   http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F50603


See http://www.whitehatsec.com/press_releases/WH-PR-20030120.pdf
    http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0035.html
    http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F50603
    http://www.kb.cert.org/vuls/id/867593

Risk factor : Medium';

 script_description(english:desc["english"]);
 
 summary["english"] = "http TRACE XSS attack";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 E-Soft Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if (get_port_state(port))
{
    if(http_is_dead(port:port))exit(0);
    
    cmd1 = http_get(item:"/thisFiledoesNotexist.html", port:port);
    cmd2 = http_get(item:"/thisFiledoesNotexist.html", port:port);
    
    cmd1 = ereg_replace(pattern:"GET /", string:cmd1, replace:"TRACE /");
    cmd2 = ereg_replace(pattern:"GET /", string:cmd2, replace:"TRACK /");
 
    soc = http_open_socket(port);
    if(!soc) exit(0);
   
    send(socket:soc, data:cmd1);
    reply = http_recv(socket:soc);
    cmd1 = cmd1 - string("\r\n\r\n");
   
    
    http_close_socket(soc); 
    if("TRACE /thisFiledoesNotexist.html HTTP/1." >< reply)
    {
	security_warning(port);
	exit(0);
    }
   

    soc = http_open_socket(port);
    if(!soc) exit(0);
    send(socket:soc, data:cmd2);
    reply = http_recv(socket:soc);
    http_close_socket(soc); 
    
    if("TRACK /thisFiledoesNotexist.html HTTP/1." >< reply)
    {
	security_warning(port);
    }
}
