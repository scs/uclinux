#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10443);
 script_cve_id("CVE-1999-0077");

 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Predictable TCP sequence number";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has predictable TCP sequence numbers.

An attacker may use this flaw to establish spoofed TCP
connections to this host.

Solution : If the remote host is running Windows, see
http://www.microsoft.com/technet/security/bulletin/ms99-046.asp

Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "TCP SEQ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
		
		
 family["english"] = "General"; 
 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("nmap_osfingerprint.nes");
 script_require_keys("Host/tcpseq");

 
 exit(0);
}



# We rely on the result of nmap_osfingerprint.nes
seq = get_kb_item("Host/tcpseq");
if(!seq) exit(0);

if(ereg(string:seq, pattern:"constant|64k|i800|time_dependant"))security_hole(0);
