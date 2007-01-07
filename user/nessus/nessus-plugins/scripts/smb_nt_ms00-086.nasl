#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10632);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(1912);
 script_cve_id("CVE-2000-0886");

 
 name["english"] =  "Webserver file request parsing";
 name["francais"] = "Webserver file request parsing";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Webserver file request parsing'
problem has not been applied.

This vulnerability can allow an attacker to make the
remote IIS server make execute arbitrary commands.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-086.asp
Risk factor : Serious";


 desc["francais"] = "
Le patch pour la vulnérabilité du parsing de requetes de fichiers
par le web n'a pas été appliqué.

Celle-ci permet à un pirate de faire executer des commandes arbitraires
au serveur web distant.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-086.asp
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q277873 is installed";
 summary["francais"] = "Détermine si le hotfix Q277873 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl"
		     );
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

version = get_kb_item("SMB/WindowsVersion");

if(version == "5.0")
{
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))
	exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q277873";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
}
