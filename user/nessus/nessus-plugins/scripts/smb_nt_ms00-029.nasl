#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10433);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(1236);
 script_cve_id("CVE-2000-0305");
 name["english"] = "NT IP fragment reassembly patch not applied (jolt2)";
 name["francais"] = "Patch for le reassemblage de fragments IP non appliqué (jolt2)";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'IP Fragment Reassembly' vulnerability
has not been applied on the remote Windows host.

This vulnerability allows an attacker to send malformed packets
which will hog this computer CPU to 100%, making
it nearly unusable for the legitimate users.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-029.asp
Risk factor : Serious";


 desc["francais"] = "
Le hotfix réglant la vulnérabilité de réassemblage
de paquets IP n'a pas été appliqué sur le Windows
distant.

Cette vulnérabilité permet à un pirate d'envoyer des paquets
malformés qui vont consommer 100% du temps CPU de l'hote
distant, le rendant inutilisable pour les utilisateurs
légitimes.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-029.asp
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q259728 is installed";
 summary["francais"] = "Détermine si le hotfix Q258728 est installé";
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
 script_exclude_keys("SMB/Win2K/ServicePack");
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

sp=get_kb_item("SMB/Win2K/ServicePack");

if(ereg(string:sp, pattern:"^Service Pack [2-9]"))exit(0);

version = get_kb_item("SMB/WindowsVersion");
#exit if XP Pro or newer
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[1-9])", string:version))exit(0);


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
item = "Comments"; 
value = registry_get_sz(key:key, item:item);
if(value)exit(0);
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q259728";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);


