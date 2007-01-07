#
# This script was written by Jøséph Mlødzianøwski <joseph@rapter.net>
# 
# 

if(description)
{

 script_id(11881);
 script_version ("$Revision: 1.1 $");
# script_cve_id("CAN-2003-00002");
 name["english"] = "Wollf backdoor detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This host appears to be running Wollf on this port. Wollf Can be used as a 
Backdoor which allows an intruder gain remote access to files on your computer. 
If you did not install this program for remote management then this host may 
be compromised.

An attacker may use it to steal your passwords, or redirect
ports on your system to launch other attacks

Solution : see www.rapter.net/jm4.htm for details on removal
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Wollf";
 
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
if(!port)port = 7614;

if(known_service(port:port))exit(0);


# Default Port of Wollf (7614)
 if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
{
 #r = recv(socket:soc, length:1024);
 s = string("pass\r\n");
 send(socket:soc, data:s);
 r = recv(socket:soc, length:1024);
 close(soc);
 if ( "Invalid password!!!" >< r ) security_hole(port);
 }
}
