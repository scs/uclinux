#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11212);
 script_cve_id("CAN-2003-0003");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0007");
 script_version("$Revision: 1.6 $");

 name["english"] = "Unchecked buffer in Locate Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The Microsoft Locate service is a name server that maps logical
names to network-specific names.

There is a security vulnerability in this server which allows
an attacker to execute arbitrary code in it by sending a specially
crafted packet to it.

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows NT 4.0
Microsoft Windows NT 4.0, Terminal Server Edition
Microsoft Windows 2000
Microsoft Windows XP

See
http://www.microsoft.com/technet/security/bulletin/ms03-001.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 810833";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;
if(!get_port_state(port))exit(0);

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("5.0" >< version)
{
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
}

if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
}


if(ereg(pattern:"(([6-9]\..*)|(5\.[2-9]))", string:version))exit(0);


# The service is not running.
svcs = get_kb_item("SMB/svcs");
if(svcs)
{
 if(!("[RpcLocator]" >< svcs))exit(0); 
}


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q810833";
item = "Comments";
value = registry_get_sz(key:key, item:item);



if(!value)security_hole(port);
exit(0);
