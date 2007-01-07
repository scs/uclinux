#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11819);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "a tftpd server is running";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a tftpd server.

Solution : If you do not use this service, you should disable it.
Risk Factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "tftpd Server detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#


if(islocalhost())exit(0);
req = raw_string(0x00, 0x01) + "nessus" + rand() + raw_string(0x00) + "netascii" + raw_string(0x00);


ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, ip_len:20, ip_id:rand(), ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
		     ip_src:this_host());
		     
myudp = forge_udp_packet(ip:ip, uh_sport:4315, uh_dport:69, uh_ulen: 8 + strlen(req), data:req);


filter = 'udp and dst port 4315 and src host ' + get_host_ip() + ' and udp[9:1]=0x05';

rep = send_packet(myudp, pcap_active:TRUE, pcap_filter:filter);	     
if(rep)
{
 data = get_udp_element(udp:rep, element:"data");
 if(ord(data[1]) == 0x05)security_note(port);
}
