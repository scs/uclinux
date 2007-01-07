#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10551);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Obtain network interfaces list via SNMP";
 name["francais"] = "Enumeration des interfaces réseau par SNMP";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script uses SNMP to obtain the list of
the network interfaces that are installed on the remote host.

Risk factor : Low";

 desc["francais"] = "
Ce script utilise SNMP pour obtenir la liste des
interfaces réseau qui sont installées sur la machine distante";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Enumerates processes via SNMP";
 summary["francais"] = "Enumeration des processus par SNMP";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 script_dependencies("snmp_default_communities.nasl");
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

#---------------------------------------------------------------------#
# Extracts the object from a reply                                    #
#---------------------------------------------------------------------#
function extract_obj(data)
{
 if(ord(data[2]) == 2)
  {
  cmty_len = ord(data[6]);
  off = 18 + cmty_len;
 }
 else
 {
  cmty_len  = ord(data[7]);
 
  off = 20 + cmty_len;
 }
 
 if ( off + 5 > strlen(data)) return NULL;

 

 len_payload = ord(data[off]);
 _obj = "";
 
 total_len = ord(data[off+5])+6;
 
 if(total_len > strlen(data)) return NULL;
 
 for(i=4;i<total_len;i=i+1)
 {
  _obj = _obj + raw_string(ord(data[off+i]));
 }
 
 _len = strlen(_obj) + 2;
# display(">len : ", _len, "\n");
 _len = _len % 255;
 _obj2 = raw_string(0x30, _len);
 _obj = _obj2 + _obj;
 
 l = strlen(_obj);
# for(i=0;i<l;i=i+1)display(hex(ord(_obj[i])), " ");
# display("\n");
 return(_obj);
}


#---------------------------------------------------------------------#
# Extracts the data from a reply                                      #
#---------------------------------------------------------------------#
function extract_data(data)
{
  if(ord(data[2]) == 2)
  {
  cmty_len = ord(data[6]);
  off1 = 18 + cmty_len;
  off = 39 + cmty_len;
 }
 else
 {
  cmty_len  = ord(data[7]);
  off1 = 20 + cmty_len;
  off = 41 + cmty_len;
 }
 
 if(off1+5 > strlen(data)) return NULL;

 off = 18 + ord(data[off1+5])+ 7 + cmty_len;
 
 if( off > strlen(data)) return NULL;
 
# display("OFF = ", off, "\n");
 _len = ord(data[off]);
 _data = ""; 


 #display("OFF :" , off, " _LEN : ", hex(_len), "\n");
 #_len =  ord(data[off+18+_len]);
 
 if( _len > strlen(data)) return NULL;
 
 
 for(i=0;i<_len;i=i+1){
 	n = ord(data[off+i+1]);
	if((n > 0x00) &&
	   !(n == 0x5C))
 	_data = _data + raw_string(ord(data[off+i+1]));
	}
 #display("data : ", _data, "\n");
 return(_data);
}







community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port) port = 161;

ifaces = "";

soc = open_sock_udp(port);

first = raw_string(0x30, 0x82, 0x00, 
		   0x0D, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01,
		   0x02, 0x02, 0x01, 0x02);
		  
id = 2;
req = get_next(id:id, community:community, object:first);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
if(strlen(r) < 48)exit(0);

nxt = extract_obj(data:r);
data = extract_data(data:r);
#display(data, "\n");
if(valid_snmp_value(value:data))
 ifaces = string(ifaces, ". ", data, "\n");



for(z=1;z<255;z=z+1)
{
req = get_next(id:id+z, community:community, object:nxt);
send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
#display("PKT LEN : ", strlen(r), "\n");
if(strlen(r) < 48)
 {
  z = 256;
 }
else
 {
 nxt = extract_obj(data:r);
 data = extract_data(data:r);
 
 if(strlen(data))
  {
  if(valid_snmp_value(value:data))
    ifaces = string(ifaces, ". ", data, "\n");
  }
 }
}

if(strlen(ifaces))
{
 report = string(
"It was possible to obtain the list of network interfaces of the\n",
"remote host via SNMP : \n\n", ifaces, "\n",
"An attacker may use this information to gain more knowledge about\n",
"the target host.\n",
"Solution : disable the SNMP service on the remote host if you do not\n",
"           use it, or filter incoming UDP packets going to this port\n",
"Risk factor : Low");
 security_warning(protocol:"udp", port:port, data:report);
}
