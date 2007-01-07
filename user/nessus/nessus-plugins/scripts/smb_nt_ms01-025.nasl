#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10668);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-0244", "CVE-2001-0245");

 script_bugtraq_id(2709);
 
 name["english"] =  "Malformed request to index server";
 name["francais"] = "Malformed request to index server";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Malformed request to index server'
problem has not been applied.

This vulnerability can allow an attacker to execute arbitrary
code on the remote host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-025.asp
Risk factor : Serious";


 desc["francais"] = "
Le patch pour la vulnérabilité de la requète mal formée au serveur
d'indexage n'a pas été appliqué.

Cette vulnérabilité permet à un pirate d'executer du code arbitraire
sur la machine distante.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms01-025.asp
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfixes Q294472 and Q296185 are installed";
 summary["francais"] = "Détermine si les hotfixes Q294472 et Q296185 sont installés";
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

version = get_kb_item("SMB/WindowsVersion");

if(version == "4.0")
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q296185";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
 
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q294472";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
}

if(version == "5.0")
{
 # check for Win2k post SP2 SRP first.
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\SP2SRP1";
 item = "Comments";
 value = string(registry_get_sz(key:key, item:item));
 if(value)exit(0);
 # then for service pack 3.
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);

 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q296185";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
}
