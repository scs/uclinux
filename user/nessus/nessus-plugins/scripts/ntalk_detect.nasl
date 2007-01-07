#
# This script was written by Noam Rathaus <noamr@securiteam.com>
# Minor modifications by Renaud Deraison <deraison@cvs.nessus.org>,
# namely :
#
#	- the report is more comprehensive
#	- the script exits if it gets no answer from the
#	  remote host at first time
#	- French translation
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10168);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0048");
 name["english"] = "Detect talkd server port and protocol version";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running a 'talkd' daemon.

talkd is the server that notifies a user that someone else wants to initiate 
a conversation with him.


Malicious hackers may use it to abuse legitimate users by conversing with 
them with a false identity (social engineering). In addition to this, an 
attacker may use this service to execute arbitrary code on your system.

Solution: 
 Disable talkd access from the network by adding the approriate rule on your 
 firewall. If you do not need talkd, comment out the relevant line in 
 /etc/inetd.conf and restart the inetd process.

See also :  http://www.cert.org/advisories/CA-1997-04.html
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect talkd server port and protocol version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 
 exit(0);
}

#
# The script code starts here
#

 if(!(get_udp_port_state(518)))exit(0);
 
 socudp518 = open_sock_udp(518);

 if (socudp518)
 {
  send(socket:socudp518, data:string("\r\n"));
  result = recv(socket:socudp518, length:1000);
  close(socudp518);
  if (result)
  {
   security_note(port:518, protocol:"udp");
  }
  else exit(0);
 }
 
 

 srcaddr = this_host();
 a1 = ereg_replace(pattern:"([0-9]*)\.[0-9]*\.[0-9]*\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a1 = a1 % 255;
                  
 a2 = ereg_replace(pattern:"[0-9]*\.([0-9]*)\.[0-9]*\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a2 = a2 % 255;
                  

 a3 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.([0-9]*)\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a3 = a3 % 255;
                  
                  
 a4 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)",
                  string:srcaddr,
                  replace:"\1"); a4 = a4 % 255;
		  
 dstaddr = get_host_ip();

 b1 = ereg_replace(pattern:"([0-9]*)\.[0-9]*\.[0-9]*\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b1 = b1 % 255;
                  
 b2 = ereg_replace(pattern:"[0-9]*\.([0-9]*)\.[0-9]*\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b2 = b2 % 255;
                  

 b3 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.([0-9]*)\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b3 = b3 % 255;
                  
                  
 b4 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)",
                  string:dstaddr,
                  replace:"\1"); b4 = b4 % 255;
		  
		  
 sendata = raw_string( 
 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x02, 0x00, 0x00, a1,   a2, 
 a3,     a4, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x04, 
 b1,     b2,   b3,   b4, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x30, 0x9F, 0x72, 0x6F, 0x6F, 0x74, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x72, 0x6F, 0x6F, 0x74, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
#  1     2     3     4     5     6     7     8     9     10

 dstport = 518;
 soc = open_sock_udp(dstport);
 send(socket:soc, data:sendata);
 result = recv(socket:soc, length:4096);
 if (result)
 {
  banner = "talkd protocol version: ";
  banner = string(banner, ord(result[0]));
  security_note(port:518, data:banner, protocol:"udp");
 }

 close(soc);
