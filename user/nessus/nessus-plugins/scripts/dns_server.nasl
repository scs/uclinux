#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11002);
 
 script_version ("$Revision: 1.3 $");
 name["english"] = "DNS Server Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
A DNS server is running on this port. If you do not use it, disable it.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "detects a running name server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);

 exit(0);
}

#
# We ask the nameserver to resolve 127.0.0.1
#

include("misc_func.inc");

req = raw_string(0x4C, 0x55, 0x01, 0x00, 0x00, 0x01,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31,
		 0x01, 0x30, 0x01, 0x30, 0x03, 0x31, 0x32, 0x37,
		 0x07, 0x49, 0x4E, 0x2D, 0x41, 0x44, 0x44, 0x52, 
		 0x04, 0x41, 0x52, 0x50, 0x41, 0x00, 0x00, 0x0C,
		 0x00, 0x01);
		 
		 
if(get_udp_port_state(53))
{
 soc = open_sock_udp(53);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);;
 if(strlen(r) > 3)
 {
  flags = ord(r[2]);
  if(flags & 0x80)security_note(port:53, protocol:"udp");
 }
}
 
 
if(get_port_state(53))
{ 
 soc = open_sock_tcp(53);
 if(!soc)exit(0);
 len = strlen(req);
 len_hi = len / 256;
 len_lo = len % 256;
 req = string(raw_string(len_hi, len_lo), req);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:20);
 if(strlen(r) > 5)
 {
  flags = ord(r[4]);
  if(flags & 0x80){
  	security_note(53);
	register_service(port: 53, proto: "dns");
	}
 }
}
 
		 
