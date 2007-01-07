#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11868);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2001-0046");
 script_bugtraq_id(2066);

 name["english"] = "SMB Registry : permissions of the SNMP key";
 name["francais"] = "SMB : Vérification des permissions de la clé SNMP";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The registry key HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters
can be modified by users who are not in the admin group.

Write access to this key allows an unprivileged user to gain additional 
privileges.

See http://www.microsoft.com/technet/security/bulletin/ms00-095.asp

Solution : use regedt32 and set the permissions of this key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the access rights of a remote key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
val = registry_get_acl(key:"SYSTEM\CurrentControlSet\Services\SNMP\Parameters");
if(!val)exit(0);

if(registry_key_writeable_by_non_admin(security_descriptor:val))
 security_hole(get_kb_item("SMB/transport"));
 
 
