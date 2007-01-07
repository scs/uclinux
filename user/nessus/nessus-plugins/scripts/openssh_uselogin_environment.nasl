#
# This script is copyright © 2001 by EMAZE Networks S.p.A.
# under the General Public License (GPL). All Rights Reserved.
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# changes by rd: description, static report

if(description)
{
 	script_id(10823);
	script_cve_id("CVE-2001-0872");
	script_bugtraq_id(3614);
	script_version("$Revision: 1.8 $");
 	name["english"] = "OpenSSH UseLogin Environment Variables";
	script_name(english:name["english"]);
 
 	desc["english"] = " 
You are running a version of OpenSSH which is older than 3.0.2.

Versions prior than 3.0.2 are vulnerable to an environment
variables export that can allow a local user to execute
command with root privileges.
This problem affect only versions prior than 3.0.2, and when
the UseLogin feature is enabled (usually disabled by default)

Solution : Upgrade to OpenSSH 3.0.2 or apply the patch for prior
versions. (Available at: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH)

Risk factor : High (If UseLogin is enabled, and locally)";
	
 	script_description(english:desc["english"]);
 
 	summary["english"] = "Checks for the remote SSH version";
 	script_summary(english:summary["english"]);
 
 	script_category(ACT_GATHER_INFO);
 
 
 	script_copyright(english:
	"This script is copyright © 2001 by EMAZE Networks S.p.A.");
  	
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
if(!port)
	port = 22;

key = string("ssh/banner/", port);
banner = tolower(get_kb_item(key));

#
# Check if a banner is already in the knowledge database
#
if(!banner)
{
  	if(get_port_state(port))
  	{
    		soc = open_sock_tcp(port);
    		
		banner = recv(socket:soc, length:1024);
    		banner = tolower(banner);
    
    		close(soc);
  	}
}


#
# If there is no banner, exit
#
if(!banner)
	exit(0);

text = banner - string("\r\n");

#
# Grepping for the  banner
#
if("openssh" >< text)
{
	#ssh-1.99-openssh_2.9.9
	if(ereg(pattern:"ssh-.*-openssh[-_](1\..*|2\..*|3\.0.[0-1]).*"
		, string:text)) 
	{
		security_hole(port);
	}
}
