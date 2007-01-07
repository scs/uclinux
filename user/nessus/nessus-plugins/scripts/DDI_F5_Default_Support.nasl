#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10820);
 script_version("$Revision: 1.5 $");
 name["english"] = "F5 Device Default Support Password";
 script_name(english:name["english"]);

 desc["english"] = "
 
This F5 Networks system still has the default
password set for the support user account. This
account normally provides read/write access to the
web configuration utility. An attacker could take
advantage of this to reconfigure your systems and
possibly gain shell access to the system with
super-user privileges.

Solution: Remove the support account entirely or
change the password of this account to something 
that is difficult to guess.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "F5 Device Default Support Password";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);

foreach port (ports)
{
  soc = http_open_socket(port);
  if (soc)
  {
    req = string("GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if (("/bigipgui/" >< buf) && ("System Command" >< buf))
    {
     security_hole(port);
    }
  }
}
