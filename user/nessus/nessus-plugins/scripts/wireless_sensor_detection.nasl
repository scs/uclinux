#
# This script is (C) Renaud Deraison  <rderaison@tenablesecurity.com>
#
# See the Nessus Scripts License for details
#
#



if(description)
{
 script_id(11559);
 script_version ("$Revision: 1.1 $");
 desc["english"] = "
The remote host is a WSP100 802.11b Remote Sensor from 
Network Chemistry.

This device sniffs data flowing on the channels used
by 802.11b and forwards it to any host which 'subscribes'
to this device.

An attacker may use this device to sniff 802.11b networks 
of the area it is deployed from across the planet.

Solution : filter incoming traffic to this host and make sure only
authorized hosts can connect to it.

Risk factor : Medium";

 name["english"] = "Network Chemistry Wireless Sensor Detection";
 script_name(english:name["english"]);


 script_description(english:desc["english"]);

 script_summary(english:"Detects Wireless Sensor");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("snmp_sysDesc.nasl");
 exit(0);
}

#
# The script code starts here
#

community = get_kb_item("SNMP/community");
if(!community)community = "public";

if(get_udp_port_state(161))
{
 soc = open_sock_udp(161);

# create GET sysdescr call

mydata = get_kb_item("SNMP/sysDesc");
if(!mydata) {
 snmpobjid = raw_string(0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00);            
 version = raw_string(0x02 , 0x01 , 0x00);
 snmplen = strlen(community) % 256;
 community = raw_string(0x04, snmplen) + community;
 pdu_type = raw_string(0xa0, 0x19);             
 request_id = raw_string(0x02,0x01,0xde);
 error_stat = raw_string(0x02,0x01,0x00);
 error_index = raw_string(0x02,0x01,0x00);
 tie_off = raw_string(0x05,0x00);


 snmpstring = version + community + pdu_type + request_id + error_stat
+ error_index + raw_string(0x30,0x0e,0x30,0x0c,0x06,0x08) + snmpobjid +
tie_off;

 tot_len = strlen(snmpstring);
 tot_len = tot_len % 256;

 snmpstring = raw_string(0x30, tot_len) +  snmpstring;

 send(socket:soc, data:snmpstring);

 mydata = recv(socket:soc, length:1025);
 if(strlen(mydata) < 48)exit(0);
 }
}

 if(!mydata)exit(0);
 if("802.11b Remote Sensor" >< mydata)security_warning(port);
