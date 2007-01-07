#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10432);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CAN-1999-0589");
 name["english"] = "SMB Registry : permissions of keys that can change common paths";
 name["francais"] = "SMB : Vérification des permissions de clés permettant de passer admin";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script checks whether the following keys can
be modified by non admins :


HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths
HKLM\Software\Microsoft\Windows\CurrentVersion\Controls Folder
HKLM\Software\Microsoft\Windows\CurrentVersion\DeleteFiles
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer
HKLM\Software\Microsoft\Windows\CurrentVersion\Extensions
HKLM\Software\Microsoft\Windows\CurrentVersion\ExtShellViews
HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings
HKLM\Software\Microsoft\Windows\CurrentVersion\ModuleUsage
HKLM\Software\Microsoft\Windows\CurrentVersion\RenameFiles
HKLM\Software\Microsoft\Windows\CurrentVersion\Setup
HKLM\Software\Microsoft\Windows\CurrentVersion\SharedDLLs
HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions
HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Compatibility
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers
HKLM\Software\Microsoft\Windows NT\CurrentVersion\drivers.desc
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32\0
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Embedding
HKLM\Software\Microsoft\Windows NT\CurrentVersion\MCI
HKLM\Software\Microsoft\Windows NT\CurrentVersion\MCI Extensions
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Ports
HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList
HKLM\Software\Microsoft\Windows NT\CurrentVersion\WOW

These keys contain paths to common programs and DLLs. If a user
can change a path, then he may put a trojan program
into another location (say C:/temp) and point to it.

Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : Serious";


 desc["francais"] = "
 
Ce script vérifie si les clés suivantes peuvent
etre modifiés par des utilisateurs non membres
du groupe admin :

HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths
HKLM\Software\Microsoft\Windows\CurrentVersion\Controls Folder
HKLM\Software\Microsoft\Windows\CurrentVersion\DeleteFiles
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer
HKLM\Software\Microsoft\Windows\CurrentVersion\Extensions
HKLM\Software\Microsoft\Windows\CurrentVersion\ExtShellViews
HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings
HKLM\Software\Microsoft\Windows\CurrentVersion\ModuleUsage
HKLM\Software\Microsoft\Windows\CurrentVersion\RenameFiles
HKLM\Software\Microsoft\Windows\CurrentVersion\Setup
HKLM\Software\Microsoft\Windows\CurrentVersion\SharedDLLs
HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions
HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Compatibility
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers
HKLM\Software\Microsoft\Windows NT\CurrentVersion\drivers.desc
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32\0
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Embedding
HKLM\Software\Microsoft\Windows NT\CurrentVersion\MCI
HKLM\Software\Microsoft\Windows NT\CurrentVersion\MCI Extensions
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Ports
HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList
HKLM\Software\Microsoft\Windows NT\CurrentVersion\WOW


Ces clés contiennent la liste des chemins vers des programmes
et DLLs communs aux utilisateurs, et si un utilisateur peut
les modifier, alors il peut mettre un cheval de troie à
un autre endroit (C:/temp par exemple) et forcer les chemins
à pointer dessus.

Solution : utilisez regedt32 et changez les permissions
de cette clé en :

	- groupe admin  : control total
	- sytem         : control total
	- tout le monde : lecture
	
	
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines the access rights of remote keys";
 summary["francais"] = "Détermine les droits d'accès de clés distantes";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");


keys[0] = "Software\Microsoft\Windows\CurrentVersion\App Paths";
keys[1] = "Software\Microsoft\Windows\CurrentVersion\Controls Folder";
keys[2] = "Software\Microsoft\Windows\CurrentVersion\DeleteFiles";
keys[3] = "Software\Microsoft\Windows\CurrentVersion\Explorer";
keys[4] = "Software\Microsoft\Windows\CurrentVersion\Extensions";
keys[5] = "Software\Microsoft\Windows\CurrentVersion\ExtShellViews";
keys[6] = "Software\Microsoft\Windows\CurrentVersion\Internet Settings";
keys[7] = "Software\Microsoft\Windows\CurrentVersion\ModuleUsage";
keys[8] = "Software\Microsoft\Windows\CurrentVersion\RenameFiles";
keys[9] = "Software\Microsoft\Windows\CurrentVersion\Setup";
keys[10] = "Software\Microsoft\Windows\CurrentVersion\SharedDLLs";
keys[11] = "Software\Microsoft\Windows\CurrentVersion\Shell Extensions";
keys[12] = "Software\Microsoft\Windows\CurrentVersion\Uninstall";
keys[13] = "Software\Microsoft\Windows NT\CurrentVersion\Compatibility";
keys[14] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers";
keys[15] = "Software\Microsoft\Windows NT\CurrentVersion\drivers.desc";
keys[16] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers32\0";
keys[17] = "Software\Microsoft\Windows NT\CurrentVersion\Embedding";
keys[18] = "Software\Microsoft\Windows NT\CurrentVersion\MCI";
keys[19] = "Software\Microsoft\Windows NT\CurrentVersion\MCI Extensions";
keys[20] = "Software\Microsoft\Windows NT\CurrentVersion\Ports";
keys[21] = "Software\Microsoft\Windows NT\CurrentVersion\ProfileList";
keys[22] = "Software\Microsoft\Windows NT\CurrentVersion\WOW";
vuln = 0;
vuln_keys = "";

val = registry_get_acl(key:"Software");
if(val == NULL) exit(0);


for(my_counter=1;my_counter<23;my_counter=my_counter+1)
{
 val = registry_get_acl(key:keys[my_counter]);
 if(val){
	if(registry_key_writeable_by_non_admin(security_descriptor:val))
		vuln_keys += string("\nHKLM\\") + keys[my_counter];
 	}
}


if(vuln)
{
report = 
"The following registry keys are writeable by users who are not in 
the admin group : " 
+
 vuln_keys
+
string("\n") +

"These keys contain paths to common programs and DLLs. If a user
can change a path, then he may put a trojan program
into another location (say C:/temp) and point to it.


Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : Serious";

 security_hole(port:port, data:report);
}

