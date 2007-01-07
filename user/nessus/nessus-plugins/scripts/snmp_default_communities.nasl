#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# Modifications :
#
# 	02/22/2000, Renaud Deraison : added more communities
#	06/08/2000, Renaud Deraison : fixed a problem in the packets sent
#       24/02/2002, Richard Lush    : Modified to find the error code
#	08/03/2002, Axel Nennker    : cisco ILMI solution
#	23/05/2002, Axel Nennker    : ONE report for this plugin
#                   some stupid HP Printers answer to every community
#
# See the Nessus Scripts License for details
#
#
#
# References:
#
# From: Raphael Muzzio (rmuzzio_at_ZDNETMAIL.COM)
# Date: Nov 15 1998 
# To: bugtraq@securityfocus.com
# Subject:  Re: ISS Security Advisory: Hidden community string in SNMP
# (http://lists.insecure.org/lists/bugtraq/1998/Nov/0212.html)
# 
# Date: Mon, 5 Aug 2002 19:01:24 +0200 (CEST)
# From:"Jacek Lipkowski" <sq5bpf@andra.com.pl>
# To: bugtraq@securityfocus.com
# Subject: SNMP vulnerability in AVAYA Cajun firmware 
# Message-ID: <Pine.LNX.4.44.0208051851050.3610-100000@hash.intra.andra.com.pl>
#
# From:"Foundstone Labs" <labs@foundstone.com>
# To: da@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
#
# CC:da@securityfocus.com, vulnwatch@vulnwatch.org
# To:"Foundstone Labs" <labs@foundstone.com>
# From:"Rob Flickenger" <rob@oreillynet.com>
# In-Reply-To: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
# Message-Id: <D8F6A4EC-ABE3-11D6-AF54-0003936D6AE0@oreillynet.com>
# Subject: Re: [VulnWatch] Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# 
# http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0
# http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15 
#

if(description)
{
 script_id(10264);
 script_version("$Revision: 1.56 $");
 script_bugtraq_id(177, 7081, 7212, 7317);
 script_cve_id("CAN-1999-0517", "CAN-1999-0186", "CAN-1999-0254", "CAN-1999-0516");
 
 name["english"] = "Default community names of the SNMP Agent";
 script_name(english:name["english"]);
 
 desc["english"] = "Simple Network Management Protocol (SNMP) is a protocol 
which can be used by administrators to remotely manage a computer or network 
device.  There are typically 2 modes of remote SNMP monitoring.  These modes 
are roughly 'READ' and 'WRITE' (or PUBLIC and PRIVATE).  If an attacker is able 
to guess a PUBLIC community string, they would be able to read SNMP data (depending 
on which MIBs are installed) from the remote device.  This information might 
include system time, IP addresses, interfaces, processes running, etc.  

If an attacker is able to guess a PRIVATE community string (WRITE or 'writeall' 
access), they will have the ability to change information on the remote machine.  
This could be a huge security hole, enabling remote attackers to wreak complete 
havoc such as routing network traffic, initiating processes, etc.  In essence, 
'writeall' access will give the remote attacker full administrative rights over the
remote machine. 
  

Risk factor : High

More Information:
http://www.securiteam.com/exploits/Windows_NT_s_SNMP_service_vulnerability.html
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Default community names of the SNMP Agent";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 exit(0);
}


#
# The script code starts here
#

def = get_kb_item("SNMP/community");
if(def)loggued = 1;
loggued = 0;

ports = make_list(161, 32789);

foreach port (ports)
{
 if(get_udp_port_state(port))
 {


comm[0]= "private";
comm[1]= "public";
comm[2]= "ilmi";
comm[3]= "ILMI";
comm[4]= "system";
comm[5]= "write";
comm[6]= "all";
comm[7]= "monitor";
comm[8]= "agent";
comm[9]= "manager";
comm[10]= "OrigEquipMfr";
comm[11]= "admin";
comm[12]= "default";
comm[13]= "password";
comm[14]= "tivoli";
comm[15]= "openview";
comm[16]= "community";
comm[17]= "snmp";
comm[18]= "snmpd"; 		# HP Snmp agent
comm[19]= "Secret C0de";
comm[20]= "security";
comm[21]= "all private";  	# Solaris 2.5.1 and 2.6
comm[22]= "rmon";
comm[23]= "rmon_admin";
comm[24]= "hp_admin";
comm[25]= "NoGaH$@!"; # Avaya
comm[26]= "0392a0";

# See http://online.securityfocus.com/bid/3758/discussion/
comm[27] = "xyzzy";
comm[28] = "agent_steal";
comm[29] = "freekevin";
comm[30] = "fubar";

# see http://www.cirt.net/cgi-bin/passwd.pl
comm[31] = "secret"; 		# for Cisco equipment
comm[32] = "cisco"; 		# for Cisco equipment
comm[33] = "apc"; 		# for APC Web/SNMP Management Card AP9606
comm[34] = "ANYCOM"; 		# for 3COM NetBuilder
comm[35] = "cable-docsis";	# for Cisco equipment
comm[36] = "c"; 		# for Cisco equipment
comm[37] = "cc"; 		# for Cisco equipment
comm[38] = "Cisco router"; 	# for Cisco equipment
comm[39] = "cascade"; 		# for Lucent equipment
comm[40] = "comcomcom"; 	# for 3COM AirConnect AP

# HP JetDirect equipement
comm[41] = "internal";
comm[42] = "blue";
comm[43] = "yellow";


report="";
count=0;

for (i = 0; comm[i]; i = i + 1)
{
	srcaddr = this_host();
	dstaddr = get_host_ip();
	community = comm[i];
	
	SNMP_BASE = 31;
	COMMUNITY_SIZE = strlen(community);
	
	sz = COMMUNITY_SIZE % 256;
	

	len = SNMP_BASE + COMMUNITY_SIZE;
	len_hi = len / 256;
	len_lo = len % 256;
	sendata = raw_string(
		0x30, 0x82, len_hi, len_lo, 
		0x02, 0x01, 0x00, 0x04,
		sz);
		
		
	sendata = sendata + community +
		raw_string( 0xA1, 
		0x18, 0x02, 0x01, 0x01, 
		0x02, 0x01, 0x00, 0x02, 
		0x01, 0x00, 0x30, 0x0D, 
		0x30, 0x82, 0x00, 0x09, 
		0x06, 0x05, 0x2B, 0x06, 
		0x01, 0x02, 0x01, 0x05, 
		0x00); 

	
	dstport = port;
	soc[i] = open_sock_udp(dstport);
	send(socket:soc[i], data:sendata);
}


for(j=0; comm[j] ; j = j + 1)
{
 result = recv(socket:soc[j], length:200, timeout:1);
 close(soc[j]);
 
 
	if (strlen(result)>0)
	{
	  if(comm[j] >< result)
	  {
	   off = 0;
	   sl = strlen(comm[j]);
          
           # Find the offset required to obtain the Error Code
           for(offset=0; offset<10; offset=offset+1)
           {
            if((ord(result[9+sl+offset]) == 0x02))
            {
		off=offset;
		offset=10;
	    }
           }

           sl=sl+off;
           noerror=1;

	   # Check the SNMP Error Status Type/Len/Value
           # Anything other than 0x00 is an error code
	   if(!(ord(result[12+sl]) == 0x02))noerror = 0;
           if(!(ord(result[13+sl]) == 0x01))noerror = 0;
           if(!(ord(result[14+sl]) == 0x00))noerror = 0;

	   if(noerror)
	   {
            count = count + 1;
	    hole_data = string("SNMP Agent responded as expected with community name: ", comm[j]);
            if (comm[j] == "ILMI") {
	     hole_data = string( hole_data, " If the target is a Cisco Product, please read http://www.cisco.com/warp/public/707/ios-snmp-ilmi-vuln-pub.shtml" );
            }
            report = report + string("\n") + hole_data;
	    if(!loggued){
	  	set_kb_item(name:"SNMP/community", value:comm[j]);
		set_kb_item(name:"SNMP/port", value:port);
		loggued = 1;
		}
	    }
	   }
	  }
	}
}


if (count > 4) {
 report = string("The device answered to more than 4 community strings.\n",
  	         "This may be a false positive or a community-less SNMP server\n",
		 "HP printers answer to all community strings.\n",
		 report);
}
if (strlen(report)) {
 security_hole(port:port, data:report, protocol:"udp");
    }
}
