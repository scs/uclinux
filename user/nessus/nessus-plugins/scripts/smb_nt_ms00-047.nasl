#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10482);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(1514);
 script_cve_id("CVE-2000-0673");
 name["english"] =  "NetBIOS Name Server Protocol Spoofing patch";
 name["francais"] = "NetBIOS Name Server Protocol Spoofing patch";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'NetBIOS Name Server Protocol Spoofing'
problem has not been applied.

This vulnerability allows a malicious user to make this
host think that its name has already been taken on the
network, thus preventing it to function properly as
a SMB server (or client).



Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-047.asp
or Security Rollup: http://support.microsoft.com/support/kb/articles/q299/4/44.asp

Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème de spoof du protocole du
serveur de noms NetBIOS n'a pas été appliqué.

Cette vulnérabilité permet à un pirate de faire croire
à ce serveur que son nom NetBIOS a déjà été pris
par une autre machine sur le réseau, ce qui l'empeche
de s'établir en tant que serveur ou client SMB.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-047.asp
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q269239 is installed";
 summary["francais"] = "Détermine si le hotfix Q269239 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
 		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

#rules nt sp <=7 win2k <=1

sp=get_kb_item("SMB/Win2K/ServicePack");

if(ereg(string:sp, pattern:"^Service Pack [2-9]"))exit(0);

version = get_kb_item("SMB/WindowsVersion");
#exit if XP Pro or newer
if (ereg(pattern:"([6-9]\.[0-9])|(5\.[1-9])", string:version))exit(0);


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
item = "Comments";

value = registry_get_sz(key:key, item:item);
if(value)exit(0);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q269239";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);
