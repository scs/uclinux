#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
#
# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP1 
# 	Media Player 6.4
#	Media Player 7.1
#
#
# Supercedes MS01-056
#

if(description)
{
 script_id(11302);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0372", "CVE-2002-0373", "CAN-2002-0615");
 script_bugtraq_id(5107, 5109, 5110);
 
 
 name["english"] = "Cumulative patch for Windows Media Player";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows Media Player is vulnerable to
various flaws :
	- A remote attacker may be able to execute arbitrary code
	  when sending a badly formed file
	  
	- A local attacker may gain SYSTEM privileges
	

Solution : 
 - see http://www.microsoft.com/technet/security/bulletin/ms02-032.asp
 - If you run Windows XP, install Service Pack 1

Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

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
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("5.1" >< version)
{
  # This is windows XP
  sp = get_kb_item("SMB/XP/ServicePack");
  if(sp && ereg(pattern:"Service Pack [1-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}

key = "SOFTWARE\Microsoft\MediaPlayer\7.0\Registration";
item = "UDBVersion";
version = registry_get_sz(key:key, item:item);
if(!version)exit(0);



if(ereg(pattern:"7\.01\..*", string:version) ||
   ereg(pattern:"6\.04\..*", string:version))
{
  key = "SOFTWARE\Microsoft\Updates\Windows Media Player\wm320920.1";
  item = "Description";
  hf = registry_get_sz(key:key, item:item);
  if(!hf)security_hole(port);
}
