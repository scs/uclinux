#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
# re-release, microsoft patched the patch, new qnumber, registry, etc

if(description)
{
 script_id(11178);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2002-1214");

 name["english"] = "Unchecked Buffer in PPTP Implementation Could Enable DOS Attacks (Q329834)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Hotfix to fix Unchecked Buffer in PPTP Implementation 
 (Q329834) is not installed.

A security vulnerability results in the Windows 2000 and 
Windows XP implementations because of an unchecked buffer
in a section of code that processes the control data used
to establish, maintain and tear down PPTP connections. By
delivering specially malformed PPTP control data to an
affected server, an attacker could corrupt kernel memory
and cause the system to fail, disrupting any work in progress
on the system. 

Impact of vulnerability: Denial of service
Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-063.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329834, Unchecked Buffer in PPTP DOS";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/WinNT4/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q329834";
item = "Comments";

if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}
 
if("5.1" >< version)
{
# fixed in SP 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}


