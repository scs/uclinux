
if(description)
{
 script_id(11846);
 name["english"] = "shareaza P2P check";
 script_name(english:name["english"]);

 desc["english"] = "
The remote server seems to be a shareaza Peer-to-Peer client,
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote system is running shareaza";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);

 exit(0);
}




port = 40017;
if(!get_udp_port_state(port))exit(0);

req = raw_string(0x47,0x4E,0x44,0x02,0x55,0x03,0x01,0x01,0x48,0x00,0x50,0x49);
soc = open_sock_udp(port);
send(socket:soc, data:req);
r = recv(socket:soc, length:256);
if (r)  security_warning(port);
exit(0);


