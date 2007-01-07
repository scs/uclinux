# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11887);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0661");
 
 name["english"] = "Buffer Overflow in Windows Troubleshooter ActiveX Control (826232)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability exists in the Microsoft Local Troubleshooter ActiveX control in 
Windows 2000. The vulnerability exists because the ActiveX control (Tshoot.ocx) contains
a buffer overflow that could allow an attacker to run code of their choice on a user's system. 
To exploit this vulnerability, the attacker would have to create a specially formed HTML based 
e-mail and send it to the user. 
Alternatively an attacker would have to host a malicious Web site that contained a Web page 
designed to exploit this vulnerability.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-042.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q826232";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Jeff Adams");
 family["english"] = "Windows";
 script_family(english:family["english"]);
  script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack.nasl",
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
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\KB826232";
 item = "Description";

# Will be fixed in Service Pack 5
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [5-9]"))exit(0);
  
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}
