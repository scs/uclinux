#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10771);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(3369);
 script_cve_id("CVE-2001-0816");
 
 name["english"] = "OpenSSH 2.5.x -> 2.9.x adv.option";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH between 2.5.x and
2.9.x

Depending on the order of the user keys in 
~/.ssh/authorized_keys2, sshd might fail to
apply the source IP based access control
restriction to the correct key.

This problem allows users to circumvent
the system policy and login from disallowed
source IP address.

Solution :
Upgrade to OpenSSH 2.9.9

Risk factor : Medium";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
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
    banner = tolower(banner);
    close(soc);
  }
}

if(!banner)exit(0);


banner = tolower(banner);

if(ereg(pattern:".*openssh[-_]2\.(([5-8]\..*)|(9\.[0-8])).*",
	string:banner))
{
 security_warning(port);
}
