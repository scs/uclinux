#
# This script is (C) Tenable Network Security
#

if(description)
{
 script_id(11897);
 script_version("$Revision: 1.7 $");
 
 name["english"] = "NetInfo daemon";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A 'NetInfo' daemon is running on this port. NetInfo is in charge of maintaining
databases (or 'maps') regarding the system. Such databases include the list
of users, the password file, and more. This service should not be reachable
directly from the network.

Solution : Filter incoming traffic to this port
Risk Factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of NetInfo";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "find_service2.nasl");
 exit(0);
}


include("misc_func.inc");

function netinfo_recv(socket)
{
 local_var buf, len;

 buf = recv(socket:soc, length:4);
 if(strlen(buf) < 4)return NULL;

 len = ord(buf[3]) + ord(buf[2])*256;

 buf += recv(socket:soc, length:len);
 if(strlen(buf) != len + 4)return NULL;
 return buf;
}


port = get_kb_item("Services/unknown");
if(!port)port = 1033;
if(known_service(port:port))exit(0);

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:raw_string(
		0x80, 0x00, 0x00, 0x28, 0x6e, 0xfd, 0x67, 0xa9,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 ,0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00));

r = netinfo_recv(socket:soc);
close(soc);
if(r && "6efd67a9" >< hexstr(r) && strlen(r) == 40 && ord(r[11]) == 0x01 && ord(r[0]) == 0x80 && ord(r[strlen(r) - 2]) == 0)
{
 register_service(port:port, proto:"netinfo");
 security_warning(port);
}
