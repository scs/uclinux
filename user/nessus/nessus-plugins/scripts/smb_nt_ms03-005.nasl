#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11231);
 script_cve_id("CAN-2003-0004");
 script_version("$Revision: 1.4 $");

 name["english"] = "Unchecked Buffer in XP Redirector (Q810577)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a flaw in the RPC redirector
which can allow a local attacker to run code of its choice
with the SYSTEM privileges.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-005.asp
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q810577";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 SECNAP Network Security");
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

if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);

if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q810577";
item = "Comments";
value = registry_get_sz(key:key, item:item);

if(!value)security_warning(port);
exit(0);
}
