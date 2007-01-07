#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10525);
 script_bugtraq_id(1743);
 script_version ("$Revision: 1.15 $");
 name["english"] = "LPC and LPC Ports Vulnerabilities patch";
 name["francais"] = "Patch pour les vulnerabilité LPC et LPC ports";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the multiple LPC and LPC Ports vulnerabilities 
has not been applied on the remote Windows host.

These vulnerabilities allows an attacker gain privileges on the
remote host, or to crash it remotely.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-070.asp
Risk factor : High";


 desc["francais"] = "
Le hotfix corrigeant les multiples vulnérabilité LPC et LPC ports
n'a pas été appliqué sur le WindowsNT distant.

Ces vulnérabilités permettent à un pirate d'obtenir plus de privilèges
sur la machine distante, ou bien de la faire planter à distance.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-070.asp
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q266433 is installed";
 summary["francais"] = "Détermine si le hotfix Q266433 est installé";
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
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#



sp = get_kb_item("SMB/Win2K/ServicePack");
	
if(sp && ereg(string:sp, pattern:"^Service Pack [2-9]"))exit(0);

version = get_kb_item("SMB/WindowsVersion");
#exit if XP Pro or newer
if (ereg(pattern:"([6-9]\.[0-9])|(5\.[1-9])", string:version))exit(0);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(value)exit(0);
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q266433";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);


