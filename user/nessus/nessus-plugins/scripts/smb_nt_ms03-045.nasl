# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11885);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0659");
 
 name["english"] = "Buffer Overrun in the ListBox and in the ComboBox (824141)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A vulnerability exists because the ListBox control and the ComboBox control 
both call a function, which is located in the User32.dll file, that contains 
a buffer overrun. An attacker who had the ability to log on to a system 
interactively could run a program that could send a specially-crafted Windows 
message to any applications that have implemented the ListBox control or the 
ComboBox control, causing the application to take any action an attacker 
specified. An attacker must have valid logon credentials to exploit the 
vulnerability. This vulnerability could not be exploited remotely. 


Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-045.asp
Risk factor : Moderate";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q824141";

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
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\KB824141";
 item = "Description";

# Will be fixed in Service Pack 5
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [5-9]"))exit(0);
  
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}

if("5.1" >< version)
{
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP2\KB824141";
 item = "Description";

# Will be fixed in Service Pack 2
 sp = get_kb_item("SMB/WinXP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}


if("5.2" >< version)
{
  key = "SOFTWARE\Microsoft\Updates\Windows Server 2003\SP1\KB824141";
 item = "Description";

# Will be fixed in Service Pack 1
 sp = get_kb_item("SMB/Win2003/ServicePack");
 if(sp)exit(0);
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}
