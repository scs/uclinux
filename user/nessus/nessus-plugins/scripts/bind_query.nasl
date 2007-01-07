#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10539);
 script_cve_id("CVE-1999-0024");
 script_bugtraq_id(678);
 script_version ("$Revision: 1.15 $");
 name["english"] = "Useable remote name server";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote name server allows recursive queries to be performed
by the host running nessusd.

If this is your internal nameserver, then forget this warning.

If you are probing a remote nameserver, then it allows anyone
to use it to resolve third parties names (such as www.nessus.org).
This allows hackers to do cache poisoning attacks against this
nameserver.

If the host allows these recursive queries via UDP,
then the host can be used to 'bounce' Denial of Service attacks
against another network or system.

See also : http://www.cert.org/advisories/CA-1997-22.html

Solution : Restrict recursive queries to the hosts that should
use this nameserver (such as those of the LAN connected to it).

If you are using bind 8, you can do this by using the instruction
'allow-recursion' in the 'options' section of your named.conf

If you are using bind 9, you can define a grouping of internal addresses
using the 'acl' command

Then, within the options block, you can explicitly state:
'allow-recursion { hosts_defined_in_acl }'

For more info on Bind 9 administration (to include recursion), see: 
http://www.nominum.com/content/documents/bind9arm.pdf

If you are using another name server, consult its documentation.

Risk factor : Serious";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote name server allows recursive queries";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("smtp_settings.nasl");

 exit(0);
}

#
# We ask the nameserver to resolve www.<user_defined_domain>
#


host = "www";
domain = get_kb_item("Settings/third_party_domain");
if(!domain)domain = "nessus.org";

h_len = strlen(host) % 255;

req = string(raw_string(h_len), host);

while(domain)
{
 p = ereg_replace(string:domain,
 		  pattern:"([^\.]*)\..*",
		  replace:"\1");
 q = ereg_replace(string:domain,
 		  pattern:"[^\.]*\.(.*)",
		  replace:"\1");
 
 len = strlen(p) % 255;
 req = string(req, raw_string(len),  p);
 if(p == domain)domain = "";
 else domain = q;		  		
}


req = raw_string(0xEF, 0xB3, 0x01, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + req + raw_string( 0x00, 0x00, 0x01,
	0x00, 0x01);
	



soc = 0;

#
# We first try to do this by TCP, then by UDP 
#
if(get_port_state(53))
{
 soc = open_sock_tcp(53);
 offset = 2;
}

if(!soc)
{
 if(!get_udp_port_state(53))exit(0);
 soc = open_sock_udp(53);
 offset = 0;
}

if(soc)
{
 if(offset)
 {
  len = strlen(req);
  req = raw_string(len/255, len%255) + req;
 }
 send(socket:soc, data:req);
 r  = recv(socket:soc, length:4096);
 close(soc);
 if(r)
 {
  #
  # We look at the flags of the remote DNS (we want 0x80 - "server
  # can do recursive queries")
  #
  if((ord(r[3+offset]) & 0x80) && (ord(r[3+offset]) & 5 == 0)){
  	if(offset)
  	 	security_warning(port:53, protocol:"tcp");
 	else
		security_warning(port:53, protocol:"udp");
	}
 }
}
