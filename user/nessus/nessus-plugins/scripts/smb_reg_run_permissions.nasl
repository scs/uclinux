#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10430);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CAN-1999-0589");
 name["english"] = "SMB Registry : permissions of keys that can lead to admin";
 name["francais"] = "SMB : Vérification des permissions de clés permettant de passer admin";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script checks whether the following keys can
be modified by non admins :


HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options

Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : High";


 desc["francais"] = "
 
Ce script vérifie si les clés suivantes peuvent
etre modifiés par des utilisateurs non membres
du groupe admin :

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options


Solution : utilisez regedt32 et changez les permissions
de cette clé en :

	- groupe admin  : control total
	- sytem         : control total
	- tout le monde : lecture
	
	
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines the access rights of a remote key";
 summary["francais"] = "Détermine les droits d'accès d'une clé distante";
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


keys[0] = "Software\Microsoft\Windows\CurrentVersion\Run";
keys[1] = "Software\Microsoft\Windows\CurrentVersion\RunOnce";
keys[2] = "Software\Microsoft\Windows\CurrentVersion\RunOnceEx";
keys[3] = "Software\Microsoft\Windows NT\CurrentVersion\AeDebug";
keys[4] = "Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

vuln = 0;
vuln_keys = "";

for(my_counter=0;my_counter<5;my_counter=my_counter+1)
{
 value = registry_get_acl(key:keys[my_counter]);
 if(value && registry_key_writeable_by_non_admin(security_descriptor:value))
 {
 vuln_keys += string("\n") + "HKLM\" + keys[my_counter];
 vuln = vuln + 1;
 }
}


if(vuln)
{
report = 
"The following registry keys are writeable by users who are not in 
the admin group : 
" 
+
 vuln_keys
+
string("\n\n") +

"These keys contain the name of the program that shall
be started when the computer starts. The users who
have the right to modify them can easily make the admin
run a trojan program which will give them admin privileges.


Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : High";

 security_hole(port:get_kb_item("SMB/transport"), data:report);
}

