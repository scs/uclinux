#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11683);
 script_cve_id("CAN-2003-0224", "CAN-2003-0225", "2003-0226");
 script_bugtraq_id(7731, 7735, 7733);

 script_version("$Revision: 1.3 $");
 name["english"] = "Cumulative Patch for Internet Information Services (Q11114)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Cumulative Patch for Microsoft IIS (Q11114)

The remote host is running a version of IIS which is vulnerable to
various flaws which may allow remote attackers to disable this
service remotely and local attackers (or remote attackers with
the ability to upload arbitrary files on this server) to 
gain SYSTEM level access on this host.


Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Internet Information Server 4.0 
Microsoft Internet Information Services 5.0 
Microsoft Internet Information Services 5.1 

See
http://www.microsoft.com/technet/security/bulletin/ms03-018.asp

Supersedes
http://www.microsoft.com/technet/security/bulletin/ms02-062.asp
http://www.microsoft.com/technet/security/bulletin/ms02-028.asp
http://www.microsoft.com/technet/security/bulletin/ms02-018.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if HF Q811114 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

key = "SYSTEM\CurrentControlSet\Services\W3SVC";
item = "ImagePath";

value = registry_get_sz(key:key, item:item);
if(!value)exit(0); # No IIS installed
if("inetinfo" >!< value)exit(0); # Not IIS

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q811114";
item = "Comments";

if("4.0" >< version)
{
 value = registry_get_sz(key:key, item:item);
 if(!value){
 	security_hole(port);
	}
 else set_kb_item(name:"SMB/Hotfixes/Q811114", value:TRUE);
 exit(0);
}


if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
}

if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
}

 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
 else set_kb_item(name:"SMB/Hotfixes/Q811114", value:TRUE);
