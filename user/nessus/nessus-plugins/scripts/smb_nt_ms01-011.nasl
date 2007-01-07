#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# MS01-011 was superceded by MS01-036

if(description)
{
 script_id(10619);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(2929);
 script_cve_id("CVE-2001-0502");
 
 name["english"] =  "Malformed request to domain controller";
 name["francais"] = "Malformed request to domain controller";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Malformed request to domain controller'
problem has not been applied.

This vulnerability can allow an attacker to disable temporarily
a Windows 2000 domain controller.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-036.asp
Risk factor : Serious";


 desc["francais"] = "
Le patch pour la vulnérabilité des de paquets de requete de controlleur
de domaine n'a pas été installé.

Cette vulnérabilité permet à un pirate de désactiver temporairement le
controlleur de domaine distant.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms01-036.asp
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q287397 is installed";
 summary["francais"] = "Détermine si le hotfix Q287397 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_exclude_keys("SMB/XP/ServicePack","SMB/WinNT4/ServicePack");
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

#check for PDC/BDC first
key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = registry_get_sz(key:key, item:item);
if(!(value == "LanmanNT"))exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(version == "5.0")
{
 # check for Win2k post SP2 SRP first.
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\SP2SPR1";
 item = "Comments";
 value = string(registry_get_sz(key:key, item:item));
 if(value)exit(0);
 # then for service pack 3.
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);

 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299687";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
}
