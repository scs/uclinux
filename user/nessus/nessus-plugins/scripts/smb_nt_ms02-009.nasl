#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10926);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(4158);
 script_cve_id("CVE-2002-0052");
 name["english"] = "IE VBScript Handling patch (Q318089)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Incorrect VBScript Handling in IE can Allow Web 
Pages to Read Local Files.

Impact of vulnerability: Information Disclosure

Affected Software: 

Microsoft Internet Explorer 5.01
Microsoft Internet Explorer 5.5 
Microsoft Internet Explorer 6.0 

See
http://www.microsoft.com/technet/security/bulletin/ms02-009.asp
and: Microsoft Article
Q319847 MS02-009 May Cause Incompatibility Problems Between
 VBScript and Third-Party Applications

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the IE VBScript Handling patch (Q318089) is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl",
		     "smb_registry_full_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/XP/ServicePack");
 exit(0);
}

include("smb_nt.inc");

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);

key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{4f645220-306d-11d2-995d-00c04f98bbc9}";
item = "Version";
value = registry_get_sz(key:key, item:item);

#7302 was original ms02-009, 7426 is updated one

if(ereg(pattern:"^([1-4],.*|5,([0-5],.*|6,0,([0-9]?[0-9]?[0-9]$|[0-6][0-9][0-9][0-9]|7([0-3]|4([01]|2[0-5])))))", string:value))
{ 
  security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
