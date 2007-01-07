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
 script_id(10965);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(4810);
 
 name["english"] = "SSH 3 AllowedAuthentication";
 name["francais"] = "SSH 3 AllowedAuthentication";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of SSH which is older than 3.1.2
and newer or equal to 3.0.0.

There is a vulnerability in this release that may, under
some circumstances, allow users to authenticate using a 
password whereas it is not explicitly listed as a valid
authentication mechanism.


An attacker may use this flaw to attempt to brute force
a password using a dictionary attack (if the passwords
used are weak).

Solution :
Upgrade to version 3.1.2 of SSH which solves this problem.

Risk factor : Low";
	
	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_exclude_keys("ssh/openssh");
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

if("openssh" >< banner)exit(0);
if("f-secure" >< banner)exit(0);


if(ereg(pattern:"3\.(0\.[0-9]+)|(1\.[01])[^0-9]*$", 
	string:banner))security_warning(port);
