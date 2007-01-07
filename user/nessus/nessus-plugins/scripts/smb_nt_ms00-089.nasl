#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10555);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(1973);
 
 name["english"] =  "Domain account lockout vulnerability";
 name["francais"] = "Domain account lockout vulnerability";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'domain account lockout' 
problem has not been applied.

This vulnerability allows a user to bypass the
domain account lockout policy, and hence attempt
to brute force a user account.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-089.asp
Risk factor : Medium";


 desc["francais"] = "
Le patch pour la vulnérabilité de verrouillage de compte
du domaine n'a pas été appliqué.

Cette vulnérabilité permet à un pirate d'outrepasser la
politique de verrouillage des comptes du domaine, et 
par conséquent lui permet de tenter d'obtenir le
mot de passe d'un compte par force brute.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-089.asp
Facteur de risque : Moyen";


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
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access", "SMB/WindowsVersion");
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
if(version == "5.0")
{
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(sp)
 {
  if(ereg(string:sp,
   	  pattern:"^Service Pack [2-9]$"))exit(0);
 }
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q274372";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port); 
}
