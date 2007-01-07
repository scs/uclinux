#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10114);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CAN-1999-0524");
 name["english"] = "icmp timestamp request";
 name["francais"] = "requête icmp timestamp";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host answers to an ICMP timestamp request. This allows an attacker 
to know the date which is set on your machine. 

This may help him to defeat all your time based authentication protocols.

Solution : filter out the ICMP timestamp requests (13), and the outgoing ICMP 
timestamp replies (14).

Risk factor : Low";

 desc["francais"] = "
La machine distante répond à une requête 
ICMP timestamp. Cela permet à un pirate
d'obtenir l'heure de votre machine.

Cela peut l'aider à déjouer vos
protocoles d'authentification basés
sur le temps.

Solution : filtrez les requetes icmp
timestamp (13) entrantes, et les
messages icmp de réponse à 
timestamp (14) sortant.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Performs an ICMP timestamp request";
 summary["francais"] = "Fait une requête ICMP timestamp";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 
 
 exit(0);
}

#
# The script code starts here
#

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

icmp = forge_icmp_packet(ip:ip,icmp_type : 13, icmp_code:0,
                          icmp_seq : 1, icmp_id : 1);
			  
filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());
for(i=0;i<5;i++)
{
 rep = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
 if(rep)
 {
 type = get_icmp_element(icmp:rep, element:"icmp_type");
 if(type == 14){
		security_warning(protocol:"icmp", port:0);
		}
  exit(0);
 }
}
