#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
#
#

if(description)
{
 script_id(11309);
 script_version("$Revision: 1.3 $");
 
 script_cve_id("CVE-2002-0049");
 script_bugtraq_id(4053);
 
 name["english"] = "Winreg registry key writeable by non-admins";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The key HKLM\CurrentControlSet\Control\SecurePipeServers\winreg 
is writeable by non-administrators.

The installation software of Microsoft Exchange sets this key to
a world-writeable mode.

Local users may use this misconfiguration to escalate their privileges on 
this host.

Solution : see http://www.microsoft.com/technet/security/ms02-003.asp
Risk factor : High (locally)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the permissions for the winreg key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_full_access.nasl",
 		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access");
 script_require_ports(139, 445);
 script_require_keys("SMB/WindowsVersion");
 exit(0);
}

include("smb_nt.inc");


val = registry_get_acl(key:"SYSTEM\CurrentControlSet\Control\SecurePipeServers\WinReg");
if(!val)exit(0);

if(registry_key_writeable_by_non_admin(security_descriptor:val))
 security_hole(get_kb_item("SMB/transport"));
