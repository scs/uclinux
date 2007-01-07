#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11458);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SMB Registry : No dial in";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

The registry key HKLM\Software\Microsoft\Windows\Policies\Network\nodialin
is set to 0. 

It means that users are allowed to dial into the remote host
(provided a modem is installed) and therefore go past the
firewall restrictions.

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

key = "Software\Microsoft\Windows\Policies\Network";
val = registry_get_dword(key:key, item:"NoDialIn");
if(val == NULL || val != 0 )exit(0);
else security_warning(port);
