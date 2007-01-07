#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10882);
 script_version ("$Revision: 1.9 $");

 
 name["english"] = "SSH protocol version 1 enabled";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote SSH daemon supports connections made
using the version 1.33 and/or 1.5 of the SSH protocol.

These protocols are not completely cryptographically
safe so they should not be used.

Solution : 
	If you use OpenSSH, set the option 'Protocol' to '2'
	If you use SSH.com's set the option 'Ssh1Compatibility' to 'no'
		
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Negotiate SSHd connections";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");

 family["english"] = "General";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ssh_proto_version.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}




function test_version(version)
{
soc = open_sock_tcp(port);
if(!soc)return(0);
str = string("SSH-", version, "-NessusSSH_1.0\n");
r = recv_line(socket:soc, length:255);
if(!ereg(pattern:"^SSH-.*", string:r))
 { 
 close(soc);
 return(0);
 }
send(socket:soc, data:str);
r = recv_line(socket:soc, length:255);
close(soc);
if(!r)return(0);
if(ereg(pattern:"^Protocol.*version", string:r))return(0);
else return(1);
}




port = get_kb_item("Services/ssh");
if(!port)port = 22;
if(!get_port_state(port))exit(0);

if(test_version(version:"9.9"))exit(0);


if((test_version(version:"1.33")) ||
   (test_version(version:"1.5")))
	{
	 security_warning(port);
	}
	
