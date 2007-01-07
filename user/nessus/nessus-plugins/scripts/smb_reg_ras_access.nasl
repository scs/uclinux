#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10567);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CAN-2001-0045");
 script_bugtraq_id(2064);

 name["english"] = "SMB Registry : permissions of the RAS key";
 name["francais"] = "SMB : Vérification des permissions de la clé RAS";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script checks whether the following key can
be modified by non admins :

HKLM\Software\Microsoft\Windows\RAS


Write access to this key allows an unprivileged user
to gain additional privileges.

See Microsoft Security Bulletin MS00-095

Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : Serious";


 desc["francais"] = "
 
La clé HKLM\Software\Microsoft\Windows\RAS est en écriture
libre pour des utilisateurs non-administrateurs.

Le fait de pouvoir modifier cette clé permet à n'importe
qui d'elever ses privileges sur cette machine.

Solution : utilisez regedt32 et changez les permissions
de cette clé en :

	- groupe admin  : control total
	- sytem         : control total
	- tout le monde : lecture
	
	
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines the access rights of a remote key";
 summary["francais"] = "Détermine les droits d'accès de la clé distante";
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

val = registry_get_acl(key:"Software\Microsoft\Windows\RAS");
if(!val)exit(0);

if(registry_key_writeable_by_non_admin(security_descriptor:val))
 security_hole(get_kb_item("SMB/transport"));
 
 
