#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10563);
 script_cve_id("CAN-2000-1039");
 script_bugtraq_id(2022);
 script_version ("$Revision: 1.14 $");

 
 name["english"] =  "Incomplete TCP/IP packet vulnerability";
 name["francais"] = "Incomplete TCP/IP packet vulnerability";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'incomplete TCP/IP packet'
problem has not been applied.

This vulnerability allows a user to prevent this host
from communicating with the network

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-091.asp
Risk factor : Serious";


 desc["francais"] = "
Le patch pour la vulnérabilité de paquets TCP/IP incomplets n'a pas
été installé.

Cette vulnérabilité permet à un pirate d'empecher cette machine
de communiquer avec le réseau.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-091.asp
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q274372 is installed";
 summary["francais"] = "Détermine si le hotfix Q274372 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl"
		     );
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access",
 		     "SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#


# nt 4.0 only.
	
version = get_kb_item("SMB/WindowsVersion");
if(version == "4.0")
{
  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
  item = "Comments";
  value = registry_get_sz(key:key, item:item);
  if(value)exit(0);
  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q275567";
  value = registry_get_sz(key:key, item:item);
  if(!value)security_hole(port);
}
