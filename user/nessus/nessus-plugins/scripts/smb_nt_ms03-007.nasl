#
# This script was written by Trevor Hemsley, by using smb_nt_ms03-005.nasl
# from Michael Scheidell as a template.
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11413);
 script_cve_id("CAN-2003-0109");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0005");
 script_bugtraq_id(7116);

 name["english"] = "Unchecked Buffer in ntdll.dll (Q815021)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a flaw in ntdll.dll
which may allow an attacker to gain system privileges,
by exploiting it thru, for instance, WebDAV in IIS5.0
(other services could be exploited, locally and/or remotely)

Note : On Win2000, this advisory is superceded by MS03-013

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-007.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q815021 non-intrusively";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Trevor Hemsley");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/samba","SMB/WinNT4/ServicePack",
		     "SMB/XP/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if("5.0" >< version)
{
 # fixed in 2000 service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))
 {
	set_kb_item(name:"SMB/Hotfixes/Q815021", value:TRUE);
	exit(0);  
 }
 
 # fixed in winwk ms03-013
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q811493";
 item = "Comments";

 value = registry_get_sz(key:key, item:item);
 if(value)
 {
  set_kb_item(name:"SMB/Hotfixes/Q815021", value:TRUE);
  exit(0);
 }

 
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q815021";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);

 if(!value)security_hole(port);
 else set_kb_item(name:"SMB/Hotfixes/Q815021", value:TRUE);
}
