#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10881);
 script_version ("$Revision: 1.8 $");

 
 name["english"] = "SSH protocol versions supported";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin determines which versions of the SSH protocol
the remote SSH daemon supports

Risk factor : None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Negotiate SSHd connections";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");

 family["english"] = "General";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ssh", 22);
 exit(0);
}



function test_version(version)
{
soc = open_sock_tcp(port);
if(!soc)return(0);
r = recv_line(socket:soc, length:255);
if(!r)return(0);
if(!ereg(pattern:"^SSH-.*", string:r)){
	close(soc);
	return(0);
	}

str = string("SSH-", version, "-NessusSSH_1.0\n");
send(socket:soc, data:str);
r = recv_line(socket:soc, length:250);
close(soc);
if(!strlen(r))return(0);
if(ereg(pattern:"^Protocol.*version", string:r))return(0);
else return(1);
}




port = get_kb_item("Services/ssh");
if(!port)port = 22;


if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

v = 0;

vers_1_33 = 0;
vers_1_5  = 0;
vers_1_99 = 0;
vers_2_0  = 0;

# Some SSHd implementations reply to anything.
if(test_version(version:"9.9"))
	{
	exit(0);
	}

if(test_version(version:"1.33"))
	{
	v = 1;
	vers_1_33 = 1;
	}
	
if(test_version(version:"1.5"))
	{
	v = 1;
	vers_1_5 = 1;
	}
	
if(test_version(version:"1.99"))
	{
	v = 1;
	vers_1_99 = 1;
	}

if(test_version(version:"2.0"))
	{
	v = 1;
	vers_2_0 = 1;
	}



report = string("The remote SSH daemon supports the following versions of the\n",
"SSH protocol :\n\n");

if(vers_1_33)report = string(report, "  . 1.33\n");
if(vers_1_5)report = string(report, "  . 1.5\n");
if(vers_1_99)report = string(report, "  . 1.99\n");
if(vers_2_0)report = string(report, "  . 2.0\n");

if(v)security_note(port:port, data:report);
