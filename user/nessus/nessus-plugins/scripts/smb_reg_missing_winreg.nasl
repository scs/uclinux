#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Microsoft Knowledgebase
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10431);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "SMB Registry : missing winreg";
 name["francais"] = "winreg manque-t-il dans la base de registres ?";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

The registry key HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg
is missing.

This key allows you to define what can be viewed in the 
registry by non administrators.


Solution : install service pack 3 if not done already, and create
and create
SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
Under this key, create the value 'Machine' as a REG_MULTI_SZ and 
put in it what you allow to be browsed remotely.

Reference : http://www.microsoft.com/technet/prodtechnol/winntas/maintain/mngntreg/admreg.asp

Risk factor : Medium";


 desc["francais"] = "
 
La clé HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg
n'existe pas.

Cette clé vous permet de définir quelle portion de la base
de registre peut etre inspectée à distance par des utilisateurs
non membres du groupe admin.

Solution : installez le SP3 si ce n'est déjà fait, et créez la clé
HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths.
Sous cette clé, créez l'entrée 'Machine' en tant que REG_MULTI_SZ
et mettez-y la liste des chemins dont vous autorisez la visite";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if the winreg key is present";
 summary["francais"] = "Détermine la clé winreg est présente";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_full_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password","SMB/registry_full_access");
 script_exclude_keys("SMB/Win2K/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0);
# false positive on win2k - they must protect it or something - mss
if(egrep(pattern:"^5.",string:version))exit(0);

key = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths";
item = "Machine";

value = registry_get_sz(key:key, item:item);
if(!value)
{
 security_hole(port);
  exit(0);
}
