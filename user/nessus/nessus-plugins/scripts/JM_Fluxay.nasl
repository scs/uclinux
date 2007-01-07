#
# This script was written by Jøséph Mlødzianøwski <joseph@rapter.net>
# 
# 

if(description)
{
 script_id(11880);
 script_version ("$Revision: 1.1 $");
# script_cve_id("CAN-2003-00002");
 name["english"] = "Fluxay Sensor Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This host appears to be running Fluxay Sensor on this port.

Fluxay Sensor is a Backdoor which allows an intruder gain
remote access to files on your computer. Similar to SubSeven
This program is installs as a Service and is password protected.
It protects itself so it is dificult to stop or remove.

An attacker may use it to steal your passwords, or use this 
computer in other attacks.

Solution : see www.rapter.net/jm3.htm for details on removal
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Fluxay Sensor";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2003 J.Mlødzianøwski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("nmap_osfingerprint.nes", "find_service.nes");
 exit(0);
}


#
# The code starts here:
#

include("misc_func.inc");

port = get_kb_item("Services/unknown");
# port = 10;

if (!port) exit(0);
if (known_service(port: port)) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

r = recv(socket:soc, length:30);
if(!r) exit(0);

if("Sensor Console Password:" >< r)  security_hole(port);
