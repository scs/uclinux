# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11886);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0660");
 
 name["english"] = "Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a vulnerability in Authenticode that, under certain low memory 
conditions, could allow an ActiveX control to download and install without 
presenting the user with an approval dialog. To exploit this vulnerability, 
an attacker could host a malicious Web Site designed to exploit this 
vulnerability. If an attacker then persuaded a user to visit that site an 
ActiveX control could be installed and executed on the user's system. 
Alternatively, an attacker could create a specially formed HTML e-mail and i
send it to the user. 

Exploiting the vulnerability would grant the attacker with the same privileges 
as the user.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-041.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823182";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Jeff Adams");
 family["english"] = "Windows";
 script_family(english:family["english"]);
  script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack.nasl",
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


if("5.0" >< version)
{
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\KB823182";
 item = "Description";

# Will be fixed in Service Pack 5
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [5-9]"))exit(0);
  
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}

if("5.1" >< version)
{
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP2\KB823182";
 item = "Description";

# Will be fixed in Service Pack 2
 sp = get_kb_item("SMB/WinXP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}


if("5.2" >< version)
{
  key = "SOFTWARE\Microsoft\Updates\Windows Server 2003\SP1\KB823182";
 item = "Description";

# Will be fixed in Service Pack 1
 sp = get_kb_item("SMB/Win2003/ServicePack");
 if(sp)exit(0);
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}
