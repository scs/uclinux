#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11803);
 script_cve_id("CAN-2003-0346");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0024");
 script_bugtraq_id(7370);
 script_version ("$Revision: 1.9 $");

 name["english"] = "DirectX MIDI Overflow (819696)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows with a version of
DirectX which is vulnerable to a buffer overflow in the module
which handles MIDI files.

To exploit this flaw, an attacker needs to craft a rogue MIDI file and
send it to a user of this computer. When the user attempts to read the
file, it will trigger the buffer overflow condition and the attacker
may gain a shell on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/MS03-030.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks hotfix 819696";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
        "smb_login.nasl","smb_registry_access.nasl",
       "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
       "SMB/WindowsVersion",
       "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");


port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

# NT4
if("4.0" >< version)
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q819696";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}

# Win2000
if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);

 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP4\KB819696";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\KB819696";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q819696";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}

if("5.1" >< version)
{


# Windows XP Gold
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP1\KB819696";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);

# Fixed in SP2
 sp = get_kb_item("SMB/WinXP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
  
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP2\KB819696";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value)exit(0);
}

# Win2003
if("5.2" >< version)
{
 # fixed in Service Pack 1
 
 
 #NT4-style
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q819696";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);
 
 
 if(!get_kb_item("SMB/registry_full_access"))exit(0);
 
 
 sp = get_kb_item("SMB/Win2003/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [1-9]"))exit(0);
 key = "SOFTWARE\Microsoft\Updates\Windows 2003 Server\SP1\KB819696";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}
