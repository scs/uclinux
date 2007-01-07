#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 
# 

if(description)
{

script_id(11854);
script_version ("$Revision: 1.1 $");
name["english"] = "FsSniffer Detection";
script_name(english:name["english"]);

desc["english"] = "
This host appears to be running FsSniffer on this port.

FsSniffer is backdoor which allows an intruder to steal
PoP3/FTP and other passwords you use on your system.

An attacker may use it to steal your passwords.

Solution : see www.rapter.net/jm1.htm for details on removal
Risk factor : High";

script_description(english:desc["english"]);

summary["english"] = "Determines the presence of FsSniffer";

script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);


script_copyright(english:"This script is Copyright (C) 2003 J.Mlodzianowski");
family["english"] = "Backdoors";
script_family(english:family["english"]);
script_dependencie("find_service.nes");
exit(0);
}


#
# The code starts here
#

include("misc_func.inc");

#port =  get_kb_item("Services/FsSniffer");
port = get_kb_item("Services/unknown");

if (!port) exit(0);
if (known_service(port: port)) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

r = recv(socket:soc, min:1, length:30);
if(!r) exit(0);

if("Control Password:" >< r) 
{
 if("RemoteNC Control Password:" >< r)
 {
  if(!get_kb_item("Services/RemoteNC"))
  {
   set_kb_item(name:"Services/RemoteNC", value:port);
   exit(0);
  }
 }
 security_hole(port);
}
