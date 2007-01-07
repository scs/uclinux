#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10486);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(1507);
 script_cve_id("CVE-2000-0663");
 name["english"] =  "Relative Shell Path patch";
 name["francais"] = "Relative Shell Path patch";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Relative Shell Path'
vulnerability has not been applied.

This vulnerability allows a malicious user
who can write to the remote system root
to cause the code of his choice to be executed by
the users who will interactively log into this
host.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-052.asp
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème du 'chemin relatif
vers le shell' n'a pas été appliqué.

Cette vulnérabilité permet à un pirate ayant la
possibilité d'écrire à la racine du disque système
distant de faire executer le programme de son
choix par les utilisateurs se connectant
interactivement à cette machine.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-052.asp
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


sp = get_kb_item("SMB/Win2K/ServicePack");
if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);

version = get_kb_item("SMB/WindowsVersion");
#exit if XP Pro or newer
if (ereg(pattern:"([6-9]\.[0-9])|(5\.[1-9])", string:version))exit(0);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(value)exit(0);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q269049";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);

