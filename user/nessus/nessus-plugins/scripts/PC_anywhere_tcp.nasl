#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10794);
 script_version ("$Revision: 1.23 $");
 name["english"] = "PC Anywhere TCP";
 name["francais"] = "PC Anywhere TCP";
 script_name(english:name["english"], francais:name["francais"]);

 
 desc["english"] = "PC Anywhere is running.

This service could be used by an attacker to partially take
control of the remote system if they obtain the
credentials necessary to log in (through a brute force
attack or by other means).

An attacker may use it to steal your password or prevent
your system from working properly.

Solution : Disable this service if you do not use it.

Risk factor : Medium";

  desc["francais"] = "PC Anywhere est activé.

Ce service peut être utilisé par des pirates pour prendre le 
controle de la machine distante.

Un pirate peut l'utiliser pour voler vos mots de passes ou
vous empecher de travailler convenablement.

Solution : Désactivez ce service si vous ne l'utilisez pas

Facteur de risque : Moyen";

  script_description(english:desc["english"], francais:desc["francais"]);


   summary["english"] = "Checks for the presence PC Anywhere";
   summary["francais"] = "Vérifie la présence de PC Anywhere";
   script_summary(english:summary["english"], francais:summary["francais"]);


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com",
                francais:"Ce script est Copyright (C) 2001 Alert4Web.com");

 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("nmap_osfingerprint.nes", "find_service.nes");
 script_require_ports("Services/unknown", 5631, 65301);
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
 soc = open_sock_tcp(port);
 if(soc)
 {
    r = recv(socket:soc, length:65535);
    if (strlen(r))
    {
    pca_ban = egrep(pattern:".*Please press.*",string:r);
    if(pca_ban)
     {
       register_service(port:port, proto:"pcanywheredata");
       security_warning(port);
       exit(0);
     }
    }
  close(soc);
 }
}



port = get_kb_item("Services/unknown");
if(port)
{
 if (known_service(port: port)) exit(0);
 if(get_port_state(port))
  probe(port:port);
}
else
{
 if(get_port_state(5631))
  probe(port:5631);
 if(get_port_state(65301))
  probe(port:65301);
}
