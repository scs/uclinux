#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11673);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Remote PC Access Server Detection";
 script_name(english:name["english"]);

 
 desc["english"] = "
The remote host is running Remote PC Access Server.

This service could be used by an attacker to partially take
control of the remote system if they obtain the
credentials necessary to log in (through a brute force
attack or by sniffing the network, as this protocol
transmits usernames and passwords in plain text).

An attacker may use it to steal your password or prevent
your system from working properly.

Solution : Disable this service if you do not use it.

Risk factor : Medium";


  script_description(english:desc["english"]);


   summary["english"] = "Checks for the presence PC Anywhere";
   script_summary(english:summary["english"]);


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("nmap_osfingerprint.nes", "find_service.nes", "find_service2.nasl");
 script_require_ports("Services/unknown", 34012);
 script_require_keys("Host/OS");
 exit(0);
}

include("misc_func.inc");

os = get_kb_item("Host/OS");
if(os)
{
 if(!("indows" >< os))exit(0);
}

function probe(port)
{
 if(get_port_state(port) == 0 ) return(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
    send(socket:soc, data:raw_string(0x28, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
    r = recv(socket:soc, length:57);
    close(soc);
    if(strlen(r) == 57 && ord(r[0]) == 0x2A) 
     {
      security_warning(port);
      register_service(proto:"remote_pc", port:port);
      exit(0);
     }
 }
}



ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:34012);
foreach port (ports)
{
 probe(port:port);
}
