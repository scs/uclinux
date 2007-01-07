#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

#defportlist= "22;80;443";
defportlist= "built-in";
# Or try this one:
# defportlist= "113;139;445";

# H D Moore & Michel Arboi's Port list :
# if you want more accurate but slower results, do uncomment the following :
# defportlist= "21;22;23;25;53;79;80;110;113;135;139;143;264;389;443;993;1454;1723;3389;8080";


if(description)
{
 script_id(10180);
 script_version ("$Revision: 1.41 $");
 name["english"] = "Ping the remote host";
 name["francais"] = "Ping la machine distante";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "This script will tcp ping the remote
host and report to the plugins knowledge base 
whether the remote host is dead or alive.

The technique used is the TCP ping, that
is, this script sends to the remote
host a packet with the flag ACK,
and the host will reply with a RST. 

You can also select the use of the traditional
ICMP ping.

Risk factor : None";

 desc["francais"] = "Ce script ping la
machine distante et rapporte dans
la base de connaissances des plugins
si la machine distante est éteinte
ou allumée.

La technique utilisée est le ping TCP,
c'est à dire que ce script envoye un
paquet TCP avec le flag ACK,
et la machine distante doit répondre
avec un RST.

Vous pouvez aussi selectionner le ping ICMP
traditionel.

Facteur de risque : Aucun";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "icmp/tcp pings the remote host";
 summary["francais"] = "Ping la machine distante via un ping tcp et/ou icmp";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_SCANNER);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Port scanners";
 family["francais"] = "Port scanners";
 script_family(english:family["english"], francais:family["francais"]);

 script_add_preference(name:"TCP ping destination port(s) :",
                       type:"entry", value:defportlist);
 script_add_preference(name:"Do a TCP ping", 
                      type:"checkbox", value:"yes");
 script_add_preference(name:"Do an ICMP ping", 
                      type:"checkbox", value:"no");		      
 script_add_preference(name:"Number of retries (ICMP) :", 
 			type:"entry", value:"10");	
			
			
 script_add_preference(name:"Make the dead hosts appear in the report",
 			type:"checkbox", value:"no");
			
 script_add_preference(name:"Log live hosts in the report",
		      type:"checkbox", value:"no");			
 exit(0);
}

#
# The script code starts here
#

function log_live()
{
 if ("yes" >< log_live)
 {
  security_note(data:"The remote host is up", port:0);
 }
 exit(0);
}
 

if(islocalhost())exit(0);

do_tcp = script_get_preference("Do a TCP ping");
if(!do_tcp)do_tcp = "yes";

test = 0;

show_dead = script_get_preference("Make the dead hosts appear in the report");
log_live = script_get_preference("Log live hosts in the report");


if("yes" >< do_tcp)
{
 test = test + 1;
 p = script_get_preference("TCP ping destination port(s) :");
 if (!p) p = defportlist;
 # display(string("Ports=",p,"\n"));
 if(p != "built-in")
 {
  dport = ereg_replace(string:p, pattern:"([^;]*);(.*)", replace:"\1");
  while (dport)
  {
   p = p - dport;
   p = p - ";";
   # display(string("Port=",dport,"\n"));
   if(tcp_ping(port:dport)){
	log_live();
 	}
   dport = ereg_replace(string:p, pattern:"([^;]*);(.*)", replace:"\1");
  }
 }
 else
 {
  if(tcp_ping())log_live();
 }
}

do_icmp = script_get_preference("Do an ICMP ping");
if(!do_icmp)do_icmp = "no"; # disabled by default (too slow)

if((do_tcp == "no") && (do_icmp == "no"))exit(0);

src = this_host();
dst = get_host_ip();
retry = script_get_preference("Number of retries (ICMP) :");
alive = 0;
if(!retry)retry = 1;

if("yes" >< do_icmp)
{ 
  j = 0;
  test = test + 1;
  filter = string("ip and src host ", get_host_ip());
  while(j < retry)
  {
   # MA 2002-02-01: we increment the IP ID. Keeping the same one is not
   # safe.
   id = 1235 +j;
   ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
 		        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
		        ip_src:this_host());
   icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
  			    icmp_seq: 1, icmp_id:1);
   # MA: I planned to add a payload to the packet, so that IDS could detect 
   # a Nessus ping. Renaud was afraid that this may break something.
   # I have to admit that even a bad script kiddy could edit the script
   # The trick was to add data:"Nessus is pinging this host",
   # or maybe just: data:"Nessus",

   rep = send_packet(pcap_active:TRUE,
   		     pcap_filter:filter,
		     pcap_timeout:1,
		     icmp);
   if(rep){
   	log_live();
	}
   j = j+1;
 }
}

if(test)
{
if("yes" >< show_dead)
{
  security_note(data:"The remote host is considered as dead - not scanning", port:0);
}
set_kb_item(name:"Host/ping_failed", value:TRUE);
}
