#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11286);
 script_cve_id("CAN-2002-0974");
 script_bugtraq_id(5478);
 
 script_version("$Revision: 1.1 $");

 name["english"] = "Flaw in WinXP Help center could enable file deletion";

 script_name(english:name["english"]);
 
 desc["english"] = "
There is a security vulnerability in the remote Windows XP Help and Support
Center which can be exploited by an attacker to delete arbitrary file
on this host.

To do so, an attacker needs to create malicious web pages that must
be visited by the owner of the remote system.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms02-060.asp
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q328940";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/samba","SMB/WinNT4/ServicePack",
		     "SMB/Win2K/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("5.1" >< version)
{
 # fixed in XP service Pack 1
 sp = get_kb_item("SMB/XP/ServicePack");
 if(sp && ereg(string:sp, pattern:"Service Pack [1-9]"))exit(0);
} 
else exit(0);


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q328940";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(!value)security_warning(port);
