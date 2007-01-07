#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10205);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CAN-1999-0651");
 name["english"] = "rlogin";
 name["francais"] = "rlogin";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running the 'rlogin' service, a remote login
daemon which allows people to log in this host and obtain an
interactive shell.

This service is dangerous in the sense thatit is not ciphered - that is, 
everyone can sniff the data that passes between the rlogin client
and the rlogin server, which includes logins and passwords as well
as the commands executed by the remote host.

You should disable this service and use openssh instead (www.openssh.com)


Solution : Comment out the 'login' line in /etc/inetd.conf and restart the 
inetd process.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of rlogin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rlogin", 513);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/rlogin");
if(!port){
	p = known_service(port:513);
	if(p && p != "rlogin")exit(0);
	port = 513;
	}

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = "root" + raw_string(0) + "root" + raw_string(0) + "ls" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024, min:1);
  if(strlen(a))
   security_warning(port);
  else
   {
   a = recv(socket:soc, length:1024, min:1);
   if(strlen(a))
    security_warning(port);
   } 
  close(soc);
 }
}

