#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref:
#  Date: Wed, 30 Apr 2003 16:34:27 +0200 (CEST)
#  From: Marco Ivaldi <raptor@mediaservice.net>
#  To: <bugtraq@securityfocus.com>
#  Subject: OpenSSH/PAM timing attack allows remote users identification
#
#

if(description)
{
 script_id(11574);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2003-0190");
 script_bugtraq_id(7482, 7467, 7342);
 
 
 name["english"] = "Portable OpenSSH PAM timing attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running OpenSSH-portable 3.6.1p1 or older.

If PAM support is enabled, an attacker may use a flaw in this version
to determine the existence or a given login name by comparing the times
the remote sshd daemon takes to refuse a bad password for a non-existant
login compared to the time it takes to refuse a bad password for a
valid login.

An attacker may use this flaw to set up  a brute force attack against
the remote host.

*** Nessus did not check whether the remote SSH daemon is actually
*** using PAM or not, so this might be a false positive

Solution : Upgrade to OpenSSH-portable 3.6.1p2 or newer
Risk Factor : Low";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";

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

banner = banner - string("\r\n");

banner = tolower(banner);
if("openssh" >< banner)
{
 if(ereg(pattern:".*openssh[-_]((1\..*p[0-9])|(2\..*p[0-9])|(3\.(([0-5](\.[0-9]*)*)p[0-9]*|6(p|\.1p1))))", string:banner))
	security_warning(port);
}


