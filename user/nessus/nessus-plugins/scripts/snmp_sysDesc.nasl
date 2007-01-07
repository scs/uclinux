#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10800);
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "Obtain OS type via SNMP";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script uses SNMP to obtain the remote operating
system type and version.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates OS via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 script_dependencie("snmp_default_communities.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}


#
# Solaris comes with a badly configured snmpd which
# always reply with the same value. We make sure the answers
# we receive are not in the list of default values usually
# answered...
#
function valid_snmp_value(value)
{
 if("/var/snmp/snmpdx.st" >< value)return(0);
 if("/etc/snmp/conf" >< value)return(0);
 if( (strlen(value) == 1) && (ord(value[0]) < 32) )return(0);
 return(1);
}

#--------------------------------------------------------------------#
# Forges an SNMP GET NEXT packet                                     #
#--------------------------------------------------------------------#
function get_next(community, id, object)
{
 len = strlen(community);
#display("len : ", len, "\n");
 len = len % 256;
 
 tot_len = 4 + strlen(community) + 12 + strlen(object) + 4;
# display(hex(tot_len), "\n");
 _r = raw_string(0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len);
 o_len = strlen(object) + 2;
 
 a_len = 13 + strlen(object);
 _r = _r + community + raw_string( 0xA1,
	a_len, 0x02, 0x01, id,   0x02, 0x01, 0x00, 0x02,
	0x01, 0x00, 0x30,o_len) + object + raw_string(0x05, 0x00);
# display("len : ", strlen(_r), "\n");
 return(_r);
}



community = get_kb_item("SNMP/community");
if(!community)exit(0);

ifaces = "";

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);

first = raw_string(0x30, 0x82, 0x00, 
		   0x0B, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01,
		   0x01, 0x01);
		  
id = 2;
req = get_next(id:id, community:community, object:first);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
if(strlen(r) < 48)exit(0);

sysDesc = "";

len = strlen(r);
if(ord(r[2]) == 0x02)
{
 start = 34 + strlen(community);
}
else
{
start = 38 + strlen(community);
}

for(i=start;i<len;i=i+1)
{
  if( (ord(r[i]) >= 10) && (ord(r[i]) <= 127) )
     sysDesc = string(sysDesc, r[i]);
}

if(valid_snmp_value(value:sysDesc))
{
set_kb_item(name:"SNMP/sysDesc", value:sysDesc);
report = string("Using SNMP, we could determine that the remote operating system is :\n", sysDesc);
security_note(port:port, data:report, protocol:"udp");
}
