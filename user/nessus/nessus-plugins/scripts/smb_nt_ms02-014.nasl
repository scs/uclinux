#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11307);
 script_version("$Revision: 1.2 $");
 
 script_bugtraq_id(4248);
 script_cve_id("CVE-2002-0070");
 
 name["english"] = "Unchecked buffer in Windows Shell";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The Windows shell of the remote host has an unchecked buffer
which can be exploited by a local attacker to run arbitrary code 
on this host. 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0 Server, Terminal Server Edition 
Microsoft Windows 2000 

Recommendation: Users using any of the affected
products should install the patch immediately.

See
http://www.microsoft.com/technet/security/bulletin/ms02-014.asp

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q216840";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access","SMB/WindowsVersion");
		     
 script_exclude_keys("SMB/XP/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("4.0" >< version)
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q313829";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}


if("5.0" >< version)
{
# fixed in Service Pack 3
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);
 fullaccess = get_kb_item("SMB/registry_full_access");

 if(fullaccess)
 {
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP3\Q313829";
 item = "Description";
 }
 else
 {
   key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q313829";
   item = "Comments";
 }
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}

