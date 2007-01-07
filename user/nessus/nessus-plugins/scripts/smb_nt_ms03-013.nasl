#
# written by Renaud Deraison <renaud@tenablesecurity.com>
#

if(description)
{
 script_id(11541);
 script_cve_id("CAN-2003-0112");
 script_bugtraq_id(7370);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Buffer overrun in NT kernel message handling";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows has a flaw in the way the kernel passes error
messages to a debugger. An attacker could exploit it to gain elevated privileges
on this host.

To successfully exploit this vulnerability, an attacker would need a local
account on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/MS03-013.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks hotfix Q811493";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
        "smb_login.nasl","smb_registry_access.nasl",
       "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
       "SMB/WindowsVersion",
       "SMB/registry_access");
 script_require_ports( 139, 445);
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
# This might be entirely wrong
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q811493";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}


if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
 fullaccess = get_kb_item("SMB/registry_full_access");

 if(fullaccess)
 {
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP4\Q811493";
 item = "Description";
 }
 else
 {
   key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q811493";
   item = "Comments";
 }
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}

if("5.1" >< version)
{
 if(!get_kb_item("SMB/registry_full_access"))exit(0);

# Windows XP Gold
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP1\Q811493";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);

# Fixed in SP2
 sp = get_kb_item("SMB/WinXP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
  
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP2\Q811493";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value)exit(0);
}
