#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10413);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CAN-1999-0659");
 name["english"] = "SMB Registry : is the remote host a PDC/BDC";
 name["francais"] = "Base de registres: l'hote distant est-il un PDC/BDC ?";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote host seems to be a Primary Domain Controller
or a Backup Domain Controller.

This can be told by the value of the registry
key ProductType under
HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions

This knowledge may be of some use to an attacker and help
him to focus his attack on this host.

Solution : filter the traffic going to this port
Risk factor : Low";


 desc["francais"] = "
L'hote distant semble être un Primary Domain Controler
ou un Backup Domain Controler.

On peut affirmer ceci grace à la valeur de la clé
ProductType de la base de registre, située sous
HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions

Cette donnée est utile pour un pirate puisqu'elle va
lui permettre de savoir qu'il faut qu'il concentre
son attaque sur cette machine.

Solution : filtrez le traffic allant vers ce port
Facteur de risque : Faible";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if the remote host is a PDC/BDC";
 summary["francais"] = "Détermine si l'hote distant est un PDC/BDC";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = registry_get_sz(key:key, item:item);

if(value == "LanmanNT")
{
 security_warning(port);
}
