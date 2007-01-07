#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11789);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2003-0350");
 script_bugtraq_id(8205);
 
 name["english"] = "Flaw in message handling through utility mgr";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host runs a version of windows which has a flaw in the way
the utility manager handles Windows messages. As a result, it is possible
for a local user to gain additional privileges on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-025.asp
 
Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q822679";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");
 script_exclude_keys("SMB/Win2003/ServicePack");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");


key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP4\KB822679";
item = "Description";



if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
 
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}
