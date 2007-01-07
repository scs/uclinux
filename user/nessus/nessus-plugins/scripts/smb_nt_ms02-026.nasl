#
# This script was written by Renaud Deraison

#
if(description)
{
 script_id(11306);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0369");
 script_bugtraq_id(4958);
 
 name["english"] = "Unchecked buffer in ASP.NET worker process";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote ASP.NET installation might be vulnerable to a buffer overflow
when an application enables StateServer mode.

An attacker may use it to cause a denial of service or run arbitrary
code with the same privileges as the process being exploited (typically
an unprivileged account).

Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-026.asp
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q322289";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

full = get_kb_item("SMB/registry_full_access");
if(!full)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);


key = "SOFTWARE\Microsoft\.NetFramework";
item  = "InstallRoot";

value = registry_get_sz(key:key, item:item);
if(!value)exit(0); # No .NET installed

key = "SOFTWARE\Microsoft\Updates\.NetFramework\1.0\S321884";
item = "Description";

value = registry_get_sz(key:key, item:item);

# Fixed in SP2
if(value)
 {
  if(ereg(pattern:"Service Pack [2-9]", string:value))exit(0);
 }

key = "SOFTWARE\Microsoft\Updates\.NetFramework\1.0\NDP10SP317396\M322289";
item = "Description";

value = registry_get_sz(key:key, item:item);
if(!value)security_warning(get_kb_item("SMB/transport"));
