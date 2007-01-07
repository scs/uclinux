#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10607);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(2347);
 script_cve_id("CVE-2001-0144");
 
 
 name["english"] = "SSH1 CRC-32 compensation attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of SSH which is 
older than version 1.2.32,
or a version of OpenSSH which is older than
2.3.0.

This version is vulnerable to a flaw which allows
an attacker to gain a root shell on this host.

Solution :
Upgrade to version 1.2.32 of SSH which solves this problem,
or to version 2.3.0 of OpenSSH

More information:
http://www.core-sdi.com/advisories/ssh1_deattack.htm

Risk factor : High";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
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
    close(soc);
  }
}

if(!banner)exit(0);


banner = tolower(banner);

if("openssh" >< banner)
{
 if(ereg(pattern:"ssh-.*-openssh(-|_)((1\..*)|2\.[0-2])",
	 string:banner))security_hole(port);
}
else
{
if(ereg(pattern:"ssh-.*-1\.2\.(2[4-9]|3[01])", string:banner))
	security_hole(port);
}
