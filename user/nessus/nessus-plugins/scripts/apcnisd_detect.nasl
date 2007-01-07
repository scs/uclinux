#
# This script was written by Renaud Deraison
#
# GPL
#

if(description)
{
  script_id(11483);
  script_version ("$Revision: 1.2 $");
 
  script_name(english:"apcnisd detection");
 
  desc["english"] = "
apcnisd is running on this port. 
This software is used to remotely manage APC 
battery backup units

You should not let everyone connect to this port

Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detects acpnisd";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "find_service2.nasl");
  script_require_ports("Services/unknown", 7000);

  exit(0);
}

include ("misc_func.inc");

port = get_kb_item("Services/unknown");
if (! port) port = 7000;
if (! get_port_state(port)) exit(0);

if (known_service(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = raw_string(0x00, 0x06) + "status";

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if("APC" >< r && "MODEL" >< r)
{
 report = '
apcnisd is running on this port. 
This software is used to remotely manage APC 
battery backup units.

Here is the information we could get about the 
unit connected to this host : \n' + r + "

You should not let everyone connect to this port

Risk factor : Low";
 register_service(port:port, proto:"apcnisd");
 security_note(port:port, data:report);
 exit(0);
}
