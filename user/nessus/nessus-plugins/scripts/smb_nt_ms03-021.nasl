#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
#
#
#

if(description)
{
 script_id(11774);
 script_version("$Revision: 1.4 $");
 script_cve_id("CAN-2003-0348");
 script_bugtraq_id(8034);
 
 name["english"] = "Windows Media Player Library Access";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
An ActiveX control included with Windows Media Player 9 Series
may allow a rogue web site to gain information about the 
remote host.

An attacker may exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, one attacker would need to set up a rogue
web site and lure a user of this host into visiting it.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-021.asp
 

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


key = "SOFTWARE\Microsoft\MediaPlayer\9.0\Registration";
item = "UDBVersion";

version = registry_get_sz(key:key, item:item);
if(!version)exit(0);


version = get_kb_item("SMB/WindowsVersion");


key = "SOFTWARE\Microsoft\Updates\Windows Media Player\wm819639";
item = "Description";
item = registry_get_sz(key:key, item:item);
if(item)exit(0);


if("5.2" >< version)
{
  # This is windows 2003
  sp = get_kb_item("SMB/Win2003/ServicePack");
  if(sp)exit(0);
  security_hole(port);
  exit(0);
}

if("5.1" >< version)
{
  # This is windows XP
  sp = get_kb_item("SMB/WinXP/ServicePack");
  if(sp && ereg(pattern:"Service Pack [2-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}

if("5.0" >< version)
{
  # This is windows 2000
  sp = get_kb_item("SMB/Win2k/ServicePack");
  if(sp && ereg(pattern:"Service Pack [5-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}
