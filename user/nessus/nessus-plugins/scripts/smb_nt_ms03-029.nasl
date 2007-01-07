#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11802);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0525");
 
 name["english"] = "Flaw in Windows Function may allow DoS (823803)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows NT 4.0 which has a flaw in 
one of its function which may allow a user to cause a denial
of service on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-029.asp
 
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 823803";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

# NT 4.0 only
if("4.0" >< version)
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q823803";
 item = "Comments";

 value = registry_get_sz(item:item, key:key);
 if(!value)security_warning(port);
}
