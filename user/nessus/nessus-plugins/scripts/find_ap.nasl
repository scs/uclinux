# Copyright 2002 by John Lampe...j_lampe@bellsouth.net
# thanks for signatures and packet dumps from Matt N., William Craig,
# Bill King, jay at kinetic dot org,  HD Moore
#
# Modifications by rd: don't use forge_udp_packet() but use a regular
# udp socket instead ; use Nessus's SNMP functions, don't hardcode the
# use of the "public" SNMP community. Use SNMP/sysDesc is present already,
# simplified the search through the sysDesc string.
#
#

#
# See the Nessus Scripts License for details
#
#

desc["english"] = "
The remote host is a Wireless Access Point.  

You should ensure that the proper physical and logical controls exist
around the AP.  A misconfigured access point may allow an attacker to
gain access to an internal network without being physically present on 
the premises.  If the access point is using an 'off-the-shelf' configuration
(such as 802.11b with 40 or 104 bit WEP encryption), the data being passed
through the access point may be vulnerable to hijacking or sniffing. 

Risk factor : Medium/Low";


if(description)
{
 script_id(11026);
 script_version ("$Revision: 1.30 $");

 name["english"] = "Access Point detection";
 script_name(english:name["english"]);


 script_description(english:desc["english"]);

 summary["english"] = "
Detects wireless access points present via TCP/IP Nmap fingerprint, 
analysis of HTTP management interface, analysis of FTP banner and
analysis of SNMP information present";

 script_summary(english:"Detects Wireless APs");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 John Lampe / Ron Gula / Stan Scalsky (Tenable Network Security)");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("snmp_sysDesc.nasl", "nmap_osfingerprint.nes");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

# list of NMAP tcp fingerprints which indicate a WAP

tcpfinger[1] = "2Wire Home Portal 100 residential gateway";
tcpfinger[2] = "Aironet AP4800E";
tcpfinger[3] = "Apple Airport Extreme Base Station";
tcpfinger[4] = "Cisco 360 Access Point";
tcpfinger[5] = "Cisco 1200 access point";
tcpfinger[6] = "D-Link 704P Boradband Gateway or DI-713P WAP";
tcpfinger[7] = "D-Link DI-713P Wireless Gateway";
tcpfinger[8] = "D-Link DRC-1000AP or 3com Access Point 2000";
tcpfinger[9] = "D-Link DWL-5000AP";
tcpfinger[10] = "Fiberline WL-1200R1";
tcpfinger[11] = "Linksys WET-11";
tcpfinger[12] = "Linksys BEFW11S4 WAP or BEFSR41 router";
tcpfinger[13] = "Linksys WAP11 Wireless AP";
tcpfinger[14] = "Linksys WAP11 or D-Link DWL-900+";
tcpfinger[15] = "Netgear FM144P";
tcpfinger[16] = "Netgear MR314";
tcpfinger[17] = "Netgear MR814";
tcpfinger[18] = "Planet WAP 1950 Wireless Access Point";
tcpfinger[19] = "SMC Barricade or D-Link DL-707 Wireless Broadband Router";
tcpfinger[20] = "SMC Barricade Wireless Broadband Router";
tcpfinger[21] = "SMC Barricade DSL Router/Modem/Wireless AP";
tcpfinger[22] = "SMC Barricade Router";
tcpfinger[23] = "US Robotics USR8022 broadband wireless router";
tcpfinger[24] = "US Robotics broadband router";
tcpfinger[25] = "ZoomAir IG-4165 wireless gateway";

# Wireless Bridges
tcpfinger[26] = "Aironet 630-2400";
tcpfinger[27] = "Aironet Wireless Bridge";
tcpfinger[28] = "ARLAN BR2000E V5.0E Radio Bridge";
tcpfinger[29] = "Cisco AIR-WGB340";
tcpfinger[30] = "Cisco WGB350 802.11b WorkGroup Bridge";
tcpfinger[31] = "Linksys WET-11 wireless ethernet bridge";
tcpfinger[32] = "Proxim Stratum MP wireless bridge";

# This one will cause lots of false positives since the full signature is:
#  Embedded device: HP Switch, Copper Mountain DSL Concentrator, Compaq 
#  Remote Insight Lights-Out remote console card, 3Com NBX 25 phone 
#  system or Home Wireless Gateway, or TrueTime NTP clock

tcpfinger[33] = "3Com NBX 25 phone system or Home Wireless Gateway";


pre = "The remote host is a Wireless Access Point (";

warning = string(").\n\nYou should ensure that the proper physical and logical
controls exist around the AP.  A misconfigured access point may allow an
attacker to gain access to an internal network without being physically
present on the premises.  If the access point is using an 'off-the-shelf'
configuration (such as 802.11b with 40 or 104 bit WEP encryption), the
data being passed through the access point may be vulnerable to hijacking
or sniffing.

Risk factor : Medium/Low");

os = get_kb_item("Host/OS");
if( os )
{
  for (i=1; tcpfinger[i]; i = i + 1) {
	if (tcpfinger[i] >< os ) {
		security_warning(port:0, data:pre+os+warning);
		exit(0);
		}
	}
}

# try to find APs via web management interface
port = 80;

sigs = make_list(
# "WLAN",    # SMC, risky
 "SetExpress.shm",   #cisco 350
 "D-Link DI-",
 "Cisco AP340",
 "Cisco AP350",
 "Linksys WAP",
 'Linksys WRT',
 "Linksys BEFW",
 "Linksys WPG",
 "SOHO Version",
 'realm="BUFFALO WBR-G54"',
 'WWW-Authenticate: Basic realm="R2 Wireless Access Platform"',
 'realm="MR814"',
 'realm="FM114P"',
 'realm="MA101"',
 'realm="MR314"',
 'realm="ME102"',
 'realm="DG824M"',
 'realm="PS111W"',
 'realm="CG814M"',
 'realm="FVM318"',
 'realm="ME103"',
 'realm="HE102"',
 'realm="HR314"',
 'realm="WG602"',
 'realm="WGR614"',
 "BCM430"		# Broadcom chips (?)
 );

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc) {
  send(socket:soc, data:http_get(item:"/", port:port));
  answer = http_recv(socket:soc);
  http_close_socket(soc);
  if (answer) {
    foreach sig (sigs) {
          if ((egrep(pattern:sig, string:answer))) {
              security_warning(port:0, data:pre+sig+warning);
              exit(0);
          }
    }
  }
 }
}


# try find APs via ftp
port = 21;
ftppos[0] = "Cisco BR500";
ftppos[1] = "WLAN AP";
ftppos[2]= "ireless";

if(get_port_state(port))
{
soc = open_sock_tcp(port);
if (soc) {
  r = recv_line(socket:soc, length:512);
  close(soc);
  if (r) {
      for (i=0; ftppos[i]; i = i + 1) {
          if ((egrep(pattern:ftppos[i], string:r))) {
               security_warning(port:0, data:pre+ftppos[i]+warning);
               exit(0);
          }
      }
  }
 }
}

# try to find APs via snmp port (rely on them leaving public community string)


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

community = get_kb_item("SNMP/community");
if(!community)exit(0);

if(get_udp_port_state(161))
{
 soc = open_sock_udp(161);

# put char string identifiers below
 snmppos[0]="AP-";                     # Compaq AP
 snmppos[1]="Base Station";
 snmppos[2]="WaveLan";
 snmppos[3]="WavePOINT-II";# Orinoco WavePOINT II Wireless AP
 snmppos[4]="AP-1000";     # Orinoco AP-1000 Wireless AP
 snmppos[5]="Cisco BR500"; # Cisco Aironet Wireless Bridge
 snmppos[6]="ireless";
 snmppos[7]="Internet Gateway Device"; # D-Link (fp-prone ?)


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
 if(!mydata)exit(0);

 check_val = valid_snmp_value(value:mydata);
 if (!check_val) exit(0);
}


flag = 0;

for (psi=0; snmppos[psi]; psi = psi + 1) {
        if(snmppos[psi] >< mydata) {
            security_warning(port:0, data:pre+snmppos[psi]+warning);
            exit(0);
        }
 }
}
