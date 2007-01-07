#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10427);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CAN-1999-0589");
 name["english"] = "SMB Registry : permissions of HKLM";
 name["francais"] = "Vérification des permissions de HKLM";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

The registry key HKEY_LOCAL_MACHINE
is writeable by users who are not in the admin group.

This allows these users to create a lot of keys on
that machine, thus they can probably to get admin easily.

Such a configuration probably means that the system
has been compromised.

Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : High";


 desc["francais"] = "

La clé HKEY_LOCAL_MACHINE
de la base de registre peut etre accédée en écriture
par des utilisateurs n'étant pas membres du groupe admin.

Ces utilisateurs peuvent faire tout et n'importe quoi
sur cette machine grace à cette clé.

Une telle configuration signifie que la machine
a été très probablement compromise.

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

val = registry_get_acl(key:"");
if(!val)exit(0);

if(registry_key_writeable_by_non_admin(security_descriptor:val))
 security_hole(get_kb_item("SMB/transport"));
