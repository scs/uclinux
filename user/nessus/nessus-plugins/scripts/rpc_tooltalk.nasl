#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10239);
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(122);
 script_cve_id("CVE-1999-0003","CVE-1999-0693");
 
 name["english"] = "tooltalk service";
 name["francais"] = "Service tooltalk";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The tooltalk RPC service is running.
An possible implementation fault in the 
ToolTalk object database server may allow an
attacker to execute arbitrary commands as
root.

*** This warning may be a false 
*** positive since the presence
*** of this vulnerability is only accurately
*** identified with local access.
    
Solution : Disable this service.
See also : CERT Advisory CA-98.11

Risk factor : High";


 desc["francais"] = "
Le service RPC tooltalk tourne.
Un problème d'implémentation
dans le serveur de base de données
d'objets Tooltalk peut permettre
à un pirate d'executer des commandes
arbitraires en tant que root.

*** Cette alerte peut etre fausse
*** puisque la présence du bug
*** n'a pas été testée
   
Solution   : désactivez ce service.
Voir aussi : CERT Advisory CA-98.11

Facteur de risque : Elevé"; 


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl", "nmap_osfingerprint.nes");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

RPC_PROG = 100083;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}



if(port)
{
 vulnerable = 0;
 os = get_kb_item("Host/OS");
 if(!os)vulnerable = 1;
 else
 {
  # QueSO signatures are not handled (too hazardous)
  if(ereg(pattern:"^\*.*", string:os))vulnerable = 1;
  else
  {
   # Nmap
   if(ereg(pattern:"Solaris|HP-UX|IRIX|AIX", string:os))
   {
   if(ereg(pattern:"Solaris 2\.[0-6]", string:os))vulnerable = 1;
   if(ereg(pattern:"HP-UX.*(10\.[1-3]0|11\.0)", string:os))vulnerable = 1;
   if(ereg(pattern:"AIX 4\.[1-3]", string:os))vulnerable = 1;
   if(ereg(pattern:"IRIX (5\..*|6\.[0-4])", string:os))vulnerable = 1;
   }
   else vulnerable = 1; # We don't know
  }
 }

 if(vulnerable)
 {
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
 }
}
