#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10944);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(4426);
 script_cve_id("CVE-2002-0151");
 name["english"] = "MUP overlong request kernel overflow Patch (Q311967)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Buffer overflow in Multiple UNC Provider (MUP) in Microsoft
Windows operating systems allows local users to cause a
denial of service or possibly gain SYSTEM privileges via a
long UNC request. 

Affected Software: 

Microsoft Windows NT 4.0 Workstation 
Microsoft Windows NT 4.0 Server 
Microsoft Windows NT 4.0 Server, Enterprise Edition 
Microsoft Windows NT 4 Terminal Server Edition 
Microsoft Windows 2000 Professional 
Microsoft Windows 2000 Server 
Microsoft Windows 2000 Advanced Server 
Microsoft Windows XP Professional 

See
http://www.microsoft.com/technet/security/bulletin/ms02-017.asp

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "checks for Multiple UNC Provider Patch (Q311967)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
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

version = string(get_kb_item("SMB/WindowsVersion"));
if(!version)exit(0);
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);

if(version == "5.0")
{
# fixed in Win2k Service Pack 3
  sp = get_kb_item("SMB/Win2K/ServicePack");
  if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);
}

if(version == "5.1")
{
# fixed in XP SP1
  sp = get_kb_item("SMB/XP/ServicePack");
  if(sp)exit(0);
}

#default to winnt (version == 4.0)
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q312895";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(!value)security_warning(port);
