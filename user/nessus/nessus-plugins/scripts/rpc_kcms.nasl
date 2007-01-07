#
# This script was written by Michael Scheidell  <scheidell at secnap.net>
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10832);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0595");
 script_bugtraq_id(2605);

 name["english"] = "Kcms Profile Server";
 script_name(english:name["english"]);
 
 desc["english"] = "
The Kodak Color Management System service is running.
The KCMS service on Solaris 2.5 could allow a local user
to write to arbitrary files and gain root access.

*** This warning may be a false 
*** positive since the presence
*** of the bug has not been tested.

Patches: 107337-02 SunOS 5.7 has been released
and the following should be out soon:
111400-01 SunOS 5.8, 111401-01 SunOS 5.8_x86

Solution : Disable suid, side effects are minimal.
http://www.eeye.com/html/Research/Advisories/AD20010409.html 
http://www.securityfocus.com/bid/2605 

See also: http://packetstorm.decepticons.org/advisories/ibm-ers/96-09

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the presence of a Kcms service";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");

 family["english"] = "RPC"; 
 script_family(english:family["english"]);
 script_dependencie("rpc_portmap.nasl", "nmap_osfingerprint.nes");
 script_require_keys("rpc/portmap");
 exit(0);
}

include("misc_func.inc");

RPC_PROG = 100221;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 vulnerable = 0;
 os = get_kb_item("Host/OS");
 if(!os)vulnerable = 1;
 else
 {
  # QueSO signatures are not handled (too hazardous)
  if(ereg(pattern:"^\*.*", string:os))vulnerable = 1;
  else
  {
   # Nmap
   if(ereg(pattern:"Solaris 2\.5", string:os))vulnerable = 1;
  }
 }

 if(vulnerable)
 {
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
 }
}
