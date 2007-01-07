#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10954);
 script_cve_id("CVE-2002-0575", "CAN-2002-0575");
 script_bugtraq_id(4560);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "OpenSSH AFS/Kerberos ticket/token passing";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH older than OpenSSH 3.2.1

A buffer overflow exists in the daemon if AFS is enabled on
your system, or if the options KerberosTgtPassing or
AFSTokenPassing are enabled.  Even in this scenario, the
vulnerability may be avoided by enabling UsePrivilegeSeparation.

Versions prior to 2.9.9 are vulnerable to a remote root
exploit. Versions prior to 3.2.1 are vulnerable to a local
root exploit.

Solution :
Upgrade to the latest version of OpenSSH

Risk factor : High";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Thomas Reinke");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;

key = string("ssh/banner/", port);
banner = get_kb_item(key);




if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(!soc)exit(0);
    banner = recv_line(socket:soc, length:1024);
    banner = tolower(banner);
    close(soc);
  }
}

if(!banner)exit(0);


banner = tolower(banner);

if(ereg(pattern:".*openssh[-_](2\..*|3\.([01].*|2\.0)).*", 
	string:banner))
{
 security_hole(port);
}
