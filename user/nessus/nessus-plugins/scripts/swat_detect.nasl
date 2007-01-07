#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# Modifications by Renaud Deraison :
#
#	- French translation
#	- script_require_ports(), script_dependencies()
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10273);
script_cve_id("CVE-2000-0935");
 script_bugtraq_id(1872);
 script_version ("$Revision: 1.11 $");
 
 
 name["english"] = "Detect SWAT server port";
 name["francais"] = "Detection de SWAT";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
SWAT (Samba Web Administration Tool) is running on this port.

SWAT allows Samba users to change their passwords, and offers to the sysadmin 
an easy-to-use GUI to configure Samba.

However, it is not recommended to let SWAT be accessed by the world, as it 
allows an intruder to attempt to brute force some accounts passwords.

In addition to this, the traffic between SWAT and web clients is not ciphered, 
so an eavesdropper can gain clear text passwords easily.

Solution: Disable SWAT access from the outside network by making your firewall 
filter this port.

If you do not need SWAT, disable it by commenting the relevant /etc/inetd.conf 
line.

Risk factor : Medium";

 desc["francais"] = "
SWAT (Samba Web Administration Tool) tourne sur
ce port.

SWAT permet aux utilisateurs de Samba de changer
leurs mots de passes, et offre à l'administrateur
système une interface graphique conviviale
pour configurer Samba.

Cependant, il n'est pas recommandé de laisser
SWAT accessible de n'importe où, car un
pirate peut utiliser ce service afin de
trouver le mot de passe d'un compte par 
force brute.

De plus, le traffic entre SWAT et les clients
n'est pas chiffré, ce qui permet à quiconque
qui peut écouter ce qu'il se passe
sur le réseau d'obtenir une liste de mots
de passes valides.

Solution : filtrez les connections
en provenance de l'exterieur vers
ce port. Si vous n'utilisez pas 
SWAT, alors désactivez-le dans
/etc/inetd.conf

Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detect SWAT server port";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/swat", 901);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/swat");
if(!port)port = 901;
if (get_port_state(port))
{
 soctcp901 = http_open_socket(port);

 if (soctcp901)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp901, data:sendata);
  banner = http_recv(socket:soctcp901);
  quote = raw_string(0x22);
  
  expect = "WWW-Authenticate: Basic realm=" + quote + "SWAT" + quote;
  
  if (expect >< banner)
  {
    security_warning(port);
  }
 }
 http_close_socket(soctcp901);
}
