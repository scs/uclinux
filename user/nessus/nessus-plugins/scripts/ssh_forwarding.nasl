#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11343);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(1949);
 script_cve_id("CVE-2000-1169");
 
 name["english"] = "OpenSSH Client Unauthorized Remote Forwarding";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running OpenSSH SSH client before 2.3.0.
 
This version  does not properly disable X11 or agent forwarding, 
which could allow a malicious SSH server to gain access to the X11 
display and sniff X11 events, or gain access to the ssh-agent.

Solution :
Patch and New version are available from OpenSSH.

Risk factor : Medium";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi",
		francais:"Ce script est Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Gain a shell remotely";
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

if(!banner)exit(0);

banner = tolower(banner);
	
# Looking for OpenSSH product version number < 2.3
if(ereg(pattern:".*openssh[_-](1|2\.[0-2])\..*",string:banner))security_warning(port);
	
	

