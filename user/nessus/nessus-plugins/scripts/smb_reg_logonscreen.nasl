#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11460);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SMB Registry : Classic Logon Screen";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The registry key HKLM\Software\Microsoft\Windows NT\WinLogon\LogonType
does not exist or is set to 1.

It means that users who attempt to log in locally will see get the
'new' WindowsXP logon screen which displays the list of users of the 
remote host.

Solution : use regedt32 and set the value of this key to 0
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the value of a remote key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");

version = get_kb_item("SMB/WindowsVersion");
if(!version) exit(0);

if("5.1" >< version) # WinXP only at this time
{
 key = "Software\Microsoft\Windows NT\WinLogon";
 val = registry_get_dword(key:key, item:"LogonType");
 if(val == NULL || val != 0)security_warning(get_kb_item("SMB/transport"));
}
