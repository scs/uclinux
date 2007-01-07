#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11341);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(2345);
 script_cve_id("CAN-2001-0471");
 
 name["english"] = "SSH1 SSH Daemon Logging Failure";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running SSH Communications Security SSH 1.2.30, or previous.

This version does not log repeated login attempts, which 
could allow remote attackers to compromise accounts 
without detection via a brute force attack.

Solution :
Patch and New version are available from SSH.

Risk factor : High";
	
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

#Looking for SSH product version number from 1.0 to 1.2.30
if(ereg(string:banner,
  	pattern:"SSH-.*-1\.([0-1]|[0-1]\..*|2\.([0-9]|1[0-9]|2[0-9]|30))[^0-9]*$", icase:TRUE))security_warning(port);



