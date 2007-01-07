#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10499);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(1613);
 script_cve_id("CVE-2000-0771");

 name["english"] =  "Local Security Policy Corruption";
 name["francais"] = "Local Security Policy Corruption";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Local Security Policy Corruption'
problem has not been applied.

This vulnerability allows a malicious user to corrupt parts of
a Windows 2000 system's local security policy, which may
prevent this host from communicating with other hosts
in this domain.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-062.asp
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème de corruption de LSA n'a pas été appliqué.

Cette vulnérabilité permet à un utilisateur malicieux de corrompre
la LSA, ce qui empechera ce poste de communiquer avec les autres
appartenant à ce domaine.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-062.asp
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q269609 is installed";
 summary["francais"] = "Détermine si le hotfix Q269609 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl"
		     );
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/Win2K/ServicePack");
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
if(version == "5.0")
{
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"^Service Pack [1-9]$"))exit(0);
 
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q269609";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}
