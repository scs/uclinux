# This script was written by Yoav Goldberg <yoavg@securiteam.com>

#
# Body of a script
#
if(description)
{
 script_name(english:"Checkpoint SecureRemote detection");
 script_id(10617);
 script_version ("$Revision: 1.6 $");

desc["english"] = "
The remote host seems to be a Checkpoint FW-1 running SecureRemote.
Letting attackers know that you are running FW-1 may enable them to
focus their attack or will make them change their attack strategy.
You should not let this information leak out.
Furthermore, an attacker can perform a denial of service attack on the
machine.

Solution:
Restrict access to this port from untrusted networks.

Risk factor : Low

For More Information:
http://www.securiteam.com/securitynews/CheckPoint_FW1_SecureRemote_DoS.html";

 script_description(english:desc["english"]); 
 script_summary(english:"Determine if a remote host is running CheckPoint's SecureRemote");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_require_ports(264);
 exit(0);
}

#
# Actual script starts here
#

SecureRemote = 0;

buffer1 = raw_string(0x41, 0x00, 0x00, 0x00);
buffer2 = raw_string(0x02, 0x59, 0x05, 0x21);

if(get_port_state(264))
	{
	soc = open_sock_tcp(264);
	if(soc)
		{
		send(socket:soc, data:buffer1);
		send(socket:soc, data:buffer2);
		response = recv(socket:soc, length:5);
		if (response == buffer1) {
				SecureRemote = 1;}
 		close(soc);	
		}
	}

if(SecureRemote)
{	
	set_kb_item(name:"Host/firewall", value:"Checkpoint Firewall-1");
	security_warning(264);
}
