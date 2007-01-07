#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11459);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SMB Registry : Do not show the last user name";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

The registry key HKLM\Software\Microsoft\Windows NT\WinLogon\DontDisplayLastUserName
is not set to 1.

It means that users who attempt to log in locally will see the name
of the last user who logged in successfully in this computer on the
screen.

Solution : use regedt32 and set the value of this key to 1
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the value of a remote key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");

key = "Software\Microsoft\Windows NT\WinLogon";
val = registry_get_dword(key:key, item:"DontDisplayLastUserName");
if( val == NULL ) exit(0); # Could not access the remote registry

if(val == 0)security_warning(get_kb_item("SMB/transport"));
