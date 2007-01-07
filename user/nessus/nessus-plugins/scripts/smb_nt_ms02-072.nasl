#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11194);
 script_cve_id("CAN-2002-1327");
 script_version("$Revision: 1.2 $");

 name["english"] = "Unchecked Buffer in XP Shell Could Enable System Compromise (329390)";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible for a malicious user to mount a buffer
overrun attack using windows XP shell.

A successful attack could have the effect of either causing
the Windows Shell to fail, or causing an attacker's code to run on
the user's computer in the security context of the user.

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows XP.

See
http://www.microsoft.com/technet/security/bulletin/ms02-072.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 329390, Flaw in Microsoft XP Shell";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/samba","SMB/WinNT4/ServicePack","SMB/Win2K/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

# xp only.
if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q329390";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
 exit(0);
}
