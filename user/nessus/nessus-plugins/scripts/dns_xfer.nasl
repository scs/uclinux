#
#
# This script was written by John Lampe <j_lampe@bellsouth.net>
# Modified by Axel Nennker <axel@nennker.de>
# Modified by Erik Anderson <eanders@pobox.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10595);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CAN-1999-0532");
 name["english"] = "DNS AXFR"; 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote name server allows DNS zone transfers to be performed.
A zone transfer will allow the remote attacker to instantly populate
a list of potential targets.  In addition, companies often use a naming
convention which can give hints as to a servers primary application
(for instance, proxy.company.com, payroll.company.com, b2b.company.com, etc.).

As such, this information is of great use to an attacker who may use it
to gain information about the topology of your network and spot new
targets.

Solution: Restrict DNS zone transfers to only the servers that absolutely
need it.

Risk factor : Medium";


 script_description(english:desc["english"]);
 summary["english"] = "Determines if the remote name server allows zone transfers";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 j_lampe@bellsouth.net");
 family["english"] = "General";
 script_family(english:family["english"]);

 # should require "Sercices/dns" but find_services.nes does not recognize dns
 # mayby copy copy some code from here to find_sercies.nes???
 # script_require_ports("Services/dns", 53);
 script_require_ports(53);
 # script_require_udp_ports(53);
 exit(0);
}

#start code

function myintstring_to_int (mychar) {
		myintrray = "0123456789";
		for (q=0; q<10; q=q+1) {
				if(myintrray[q] == mychar) return (q + 48);
		}
}

#create UDP DNS header
get_host_by_addr = raw_string(0xB8, 0x4C, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

#Add in reversed octet order IP addr

myip = get_host_ip();
len = strlen(myip);          
counter=0;
for (flag = len; flag > 0; flag = flag - 1) {
  if (myip[flag-1] == ".")  {
    get_host_by_addr = get_host_by_addr + raw_string(counter);
    for (tcount = flag; tcount < flag + counter; tcount = tcount + 1) {
	  mcount = temprray[tcount];
      get_host_by_addr = get_host_by_addr + raw_string(mcount);
    }     
	for (mu=0; mu<15; mu=mu+1) {temprray[mu]=0;}
    counter = 0;
  } else {
    temprray[flag-1] = myintstring_to_int(mychar:myip[flag-1]);
    counter = counter + 1;
  }          
}            

get_host_by_addr = get_host_by_addr + raw_string(counter);
for (tcount=flag; tcount<flag + counter; tcount = tcount + 1) {
	  mcount = temprray[tcount];
	  get_host_by_addr = get_host_by_addr + raw_string(mcount);
}

#add in in-addr.arpa
get_host_by_addr = get_host_by_addr +  raw_string(0x07, 0x69, 0x6E, 0x2D, 0x61, 0x64,
                                                  0x64, 0x72, 0x04, 0x61, 0x72, 0x70,
                                                  0x61);


get_host_by_addr = get_host_by_addr + raw_string(0x00, 0x00, 0x0C, 0x00, 0x01);


#start putting together the TCP DNS zone transfer request
pass_da_zone = raw_string(
                          0x68, 0xB3,   # ID
                          0x00, 0x00,   # QR|OC|AA|TC|RD|RA|Z|RCODE
						  0x00, 0x01,   # QDCOUNT
						  0x00, 0x00,   #ANCOUNT
						  0x00, 0x00,   #NSCOUNT
						  0x00, 0x00);  #ARCOUNT
						  
  soc = open_sock_udp(53);
  if(soc) {
    send(socket:soc, data:get_host_by_addr);
    myreturn = recv(socket:soc, length:4096);
    # maybe save this info to kb as "Port/udb/53=1" if (strlen(myreturn>0))
	if(strlen(myreturn) < 7) exit(0);
	ancount = ord(myreturn[7]);       
    if (ancount == 0x01) {
	  jump = 12;
	  while (!(ord(myreturn[jump]) == 0)) {      
			 jump = jump + ord(myreturn[jump]) + 1;
	  }
	  jump = jump + 17;         
	  for (theta=1; theta < ancount; theta=theta + 1) {
			while (!(ord(myreturn[jump]) == 0)) {
				jump = jump + ord(myreturn[jump]) + 1;
			}
			jump = jump + 13;
	  }
	  jump = jump + ord(myreturn[jump]) + 1;
      while (!(ord(myreturn[jump]) == 0)) {
        pass_da_zone = pass_da_zone + raw_string(myreturn[jump]);
        jump = jump + 1;    
      }
	} else {
		close(soc);
		exit(0);
	}
	close(soc);
  }  



pass_da_zone = pass_da_zone + raw_string (0x00,         #NULL Terminator
                                          0x00, 0xFC,   # QTYPE=252=ZoneTransfer
                                          0x00, 0x01);  # QCLASS=1=Internet


len = strlen(pass_da_zone);

len_hi = len / 256;
len_lo = len % 256;

pass_da_zone = raw_string(len_hi, len_lo) + pass_da_zone;
if (!get_port_state(53))exit(0);
soctcp = open_sock_tcp(53);
if (!soctcp) exit(0);

  send(socket:soctcp, data:pass_da_zone);
  incoming  = recv(socket:soctcp, length:2);
  if (strlen(incoming) < 2) exit(0);
  len_hi = ord(incoming[0]);
  len_lo = ord(incoming[1]);

  len = len_hi * 256;
  len = len + len_lo;
  incoming = "";
  # don't want an infinite loop, if answer is illegal
  if (len < 0) exit(0);
  # only interessted in incoming[7]
  if (len > 8) len = 8;
  incoming = recv(socket:soctcp, length:len, min: len);

  if( (ord(incoming[7])) >= 0x01) {   # Is ANCOUNT == 1
      security_warning(53);
   }
  close(soctcp);

  exit(0);
