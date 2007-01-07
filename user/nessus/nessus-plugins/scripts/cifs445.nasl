#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11011);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "SMB on port 445";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote port 445 is open while port 139 is not. 

Port 445 is used for 'Netbios-less' communication between
two Windows 2000 hosts. An attacker may use it to obtain
and access shares, gain a list of usernames and so on...

Solution : filter incoming traffic to this port
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for openness of port 445";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");

 family["english"] = "Windows";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports(139, 445);
 exit(0);
}

#
# The script code starts here
#

include("smb_nt.inc");
include("misc_func.inc");

flag = 0;

if(get_port_state(445))
{
 soc = open_sock_tcp(445);
 if(soc){
 r = smb_neg_prot(soc:soc);
 close(soc);
 if(r){
 	register_service(port:445, proto:"cifs");
	security_note(port:445, data:"A CIFS server is running on this port");
	set_kb_item(name:"SMB/transport", value:445);
	flag = 1;
      }
   }
}


if(get_port_state(139))
{
  soc = open_sock_tcp(139);
  if(soc){
	nb_remote = netbios_name(orig:string("Nessus", rand()));
 	nb_local  = netbios_redirector_name();
 	session_request = raw_string(0x81, 0x00, 0x00, 0x44) + 
		  raw_string(0x20) + 
		  nb_remote +
		  raw_string(0x00, 0x20)    + 
		  nb_local  + 
		  raw_string(0x00);
	send(socket:soc, data:session_request);
	r = recv(socket:soc, length:4);
	close(soc);
	if(r && (ord(r[0]) == 0x82 || ord(r[0]) == 0x83)) {
		register_service(port:139, proto:"smb");
		security_note(port:139, data:"An SMB server is running on this port");	
    		if(!flag)set_kb_item(name:"SMB/transport", value:139);
		}
	}
}

