#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11792);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0351");
 
 name["english"] = "Buffer overrun in Windows Shell (821557)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows which has a flaw in 
its shell. An attacker could exploit it by creating a malicious Desktop.ini
file which triggers the flaw, and put it on a shared folder and wait
for someone to browse it.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-027.asp
 
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823980";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");
 script_exclude_keys("SMB/Win2003/ServicePack");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");


# XP only
if("5.1" >< version)
{
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP2\KB821557";
 item = "Comments";

# fixed in Service Pack 2
 sp = get_kb_item("SMB/WinXP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}
