#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Vulnerability found by Russell Handorf <rhandorf@mail.russells-world.com>

if(description)
{
 script_id(10724);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(3017);
 name["english"] = "Cayman DSL router one char login";
 name["francais"] = "Login d'un char cayman";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote router allows anybody to log in as
the character 'opening brace'.

An intruder may connect to it and gather valuable
information.

Solution : Contact cayman (see http://cayman.com/security.html)
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Notifies that the remote cayman router allows one char logins";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/telnet");
if(!port) port = 23;

login = raw_string(0x7D);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_init(soc);
  if("login" >< buf)
  	{
	 r = recv(socket:soc, length:2048);
	 b = buf + r;
	 send(socket:soc, data:string(login, "\r\n"));
	 r = recv(socket:soc, length:2048);
	 send(socket:soc, data:string("\r\n"));
	 r = recv(socket:soc, length:4096);
	 if("completed login" >< b)security_hole(port);
	}
  close(soc);
 }
}
