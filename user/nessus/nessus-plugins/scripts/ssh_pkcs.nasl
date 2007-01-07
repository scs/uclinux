#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11342);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(2344);
 script_cve_id("CVE-2001-0361");
 
 name["english"] = "PKCS 1 Version 1.5 Session Key Retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running SSH protocol version 1.5.

This version allows a remote attacker to decrypt and/or alter traffic via 
an attack on PKCS#1 version 1.5 knows as a Bleichenbacher attack. 
OpenSSH up to version 2.3.0, AppGate, and SSH Communications 
Security ssh-1 up to version 1.2.31 have the vulnerability present, 
although it may not be exploitable due to configurations.

Solution :
Patch and New version are available from SSH/OpenSSH.

Risk factor : Low";
	
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


if(!banner){
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 banner = recv_line(socket:soc, length:4096);
 close(soc);
 if(strlen(banner))set_kb_item(name:key, value:banner);
 }

if(!banner)exit(0);

#Looking for SSH product version number from 1.0 to 1.2.31
if(ereg(string:banner,
  	pattern:"SSH-.*-1\.([0-1]|[0-1]\..*|2\.([0-9]|1[0-9]|2[0-9]|30|31))[^0-9]*$", icase:TRUE))security_warning(port);
else {
	if(ereg(pattern:".*openssh[-_](1|2\.([0-2]\.|3\.0)).*",string:banner, icase:TRUE))security_warning(port);
		
}


