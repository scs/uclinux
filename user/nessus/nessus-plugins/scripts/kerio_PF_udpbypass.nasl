# This script was written by Renaud Deraison <rderaison@tenablesecurity.com>
#
# GNU Public Licence
#
# References:
#  http://www.securiteam.com/securitynews/5FP0N1P9PI.html
#
#
# Problem: This check is prone to false negatives (if the remote FW
#          does not allow outgoing icmp-unreach packets [default on kerio]).
#	   However I've decided to include this plugin anyway as it might
#	   uncover issues in other firewalls.
# 

if (description)
{
  script_id(11580);
  script_version ("$Revision: 1.3 $");
  script_bugtraq_id(7436);
 
 name["english"] = "UDP packets with source port of 53 bypass firewall rules";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to by-pass the rules of the remote firewall
by sending UDP packets with a source port equal to 53.

An attacker may use this flaw to inject UDP packets to the remote
hosts, in spite of the presence of a firewall.

Solution : Review your firewall rules policy
Risk Factor : High";


  script_description(english:desc["english"]);
 
  summary["english"] = "By-passes the remote firewall rules";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK); 
  script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
  family["english"] = "Firewalls";
  script_family(english:family["english"]);
  exit(0);
}


function check(sport)
{
 ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :this_host()
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport:sport,
        uh_dport:1026,
        uh_ulen :8
        );
	
  filter = string("src host ", get_host_ip(), " and dst host ", this_host(),
 " and icmp and (icmp[0] == 3  and icmp[28:2]==", sport, ")");
  for(i=0;i<6;i++)
  	{
  	res = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
	if(!isnull(res))return(1);
	}
 return(0);
}

if(check(sport:1025) == 1)
{
 exit(0);
}

if(check(sport:53) == 1)
{
 security_hole(proto:"udp", port:0);
}
