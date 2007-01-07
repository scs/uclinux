# Script for checking MS03-023 Written by Jeff Adams <jeffrey.adams@hqda.army.mil>

if(description)
{
 script_id(11878);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0469");
 
 name["english"] = "Buffer Overrun In HTML Converter Could Allow Code Execution (823559)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the way the HTML converter for Microsoft Windows handles a 
conversion request during a cut-and-paste operation. This flaw causes a 
security vulnerability to exist. A specially crafted request to the HTML 
converter could cause the converter to fail in such a way that it could 
execute code in the context of the currently logged-in user. Because this 
functionality is used by Internet Explorer, an attacker could craft a 
specially formed Web page or HTML e-mail that would cause the HTML converter 
to run arbitrary code on a user's system. A user visiting an attacker's Web 
site could allow the attacker to exploit the vulnerability without any other 
user action.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-023.asp
 
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823559";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Written by Jeff Adams");
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
 key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\KB823559";
 item = "Description";

# Will be fixed in Service Pack 5
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [5-9]"))exit(0);
  
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}

if("5.1" >< version)
{
 key = "SOFTWARE\Microsoft\Updates\Windows XP\SP2\KB823559";
 item = "Description";

# Will be fixed in Service Pack 2
 sp = get_kb_item("SMB/WinXP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}


if("5.2" >< version)
{
  key = "SOFTWARE\Microsoft\Updates\Windows Server 2003\SP1\KB823559";
 item = "Description";

# Will be fixed in Service Pack 1
 sp = get_kb_item("SMB/Win2003/ServicePack");
 if(sp)exit(0);
 
 value = registry_get_sz(item:item, key:key);
 if(!value)security_hole(port);
}
