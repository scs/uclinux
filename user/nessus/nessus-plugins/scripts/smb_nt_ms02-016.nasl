#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10945);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(4438);
 script_cve_id("CVE-2002-0051");
 name["english"] = "Opening Group Policy Files (Q318089)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Windows 2000 allows local users to prevent the application
of new group policy settings by opening Group Policy files
with exclusive-read access.

Attacker could block application of Group Policy

Affected Software: 

Microsoft Windows 2000 Server 
Microsoft Windows 2000 Advanced Server 
Microsoft Windows 2000 Datacenter Server 

See
http://www.microsoft.com/technet/security/bulletin/ms02-016.asp

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the Group Policy patch (Q318593) is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access","SMB/WindowsVersion");
 script_exclude_keys("SMB/WinNT4/ServicePack","SMB/XP/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

# only for SERVER, and only for win2k
version = get_kb_item("SMB/WindowsVersion");
if(!(version == "5.0"))exit(0);

key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = registry_get_sz(key:key, item:item);
if(!(value == "LanmanNT"))exit(0);

# fixed in Service Pack 3
sp = get_kb_item("SMB/Win2K/ServicePack");
if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q318593";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(!value)security_warning(port);
