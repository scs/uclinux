#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10229);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(866, 8615);
 script_cve_id("CVE-1999-0977");
 
 name["english"] = "sadmin service";
 name["francais"] = "Service sadmin";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The sadmin RPC service is running. 
There is a bug in Solaris versions of
this service that allow an intruder to
execute arbitrary commands on your system.

Solution : disable this service
Risk factor : High";


 desc["francais"] = "
Le service RPC sadmin tourne.
Il y a un bug dans certaines versions
de ce service qui permettent à un pirate
d'executer des commandes arbitraires sur
votre système.


Solution : désactivez ce service
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks the presence of a RPC service";
 summary["francais"] = "vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#


include("misc_func.inc");


RPC_PROG = 100232;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
}
