#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
#
# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP2
#	Media Player 7.1
#
#

if(description)
{
 script_id(11595);
 script_version("$Revision: 1.4 $");
 script_cve_id("CAN-2003-0228");
 
 name["english"] = "Windows Media Player Skin Download Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of Windows Media player which is
vulnerable to a directory traversal through its handling of 'skins'.

An attacker may exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, one attacker would need to craft a specially
malformed skin and send it to a user of this host, either directly
by e-mail or by sending a URL pointing to it.

Affected Software:

 - Microsoft Windows Media Player 7.1
 - Microsoft Windows Media Player for Windows XP (Version 8.0)


Solution : 
 - see http://www.microsoft.com/technet/security/bulletin/ms03-017.asp
 - If you run Windows XP, install Service Pack 2

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
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
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
  if(sp && ereg(pattern:"Service Pack [2-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}

key = "SOFTWARE\Microsoft\MediaPlayer\9.0\Registration";
item = "UDBVersion";
version = registry_get_sz(key:key, item:item);
if(version)exit(0);  # does not apply to media player 9.0


key = "SOFTWARE\Microsoft\MediaPlayer\7.1\Registration";
item = "UDBVersion";
version = registry_get_sz(key:key, item:item);
if(!version)
{
 key = "SOFTWARE\Microsoft\MediaPlayer\7.0\Registration";
 item = "UDBVersion";
 version = registry_get_sz(key:key, item:item);
 if(!version)
 {
 key = "SOFTWARE\Microsoft\MediaPlayer\8.0\Registration";
 item = "UDBVersion";
 version = registry_get_sz(key:key, item:item);
 if(!version)exit(0);
 }
}

key = "SOFTWARE\Microsoft\Updates\Windows Media Player\wm817787";
item = "Description";
hf = registry_get_sz(key:key, item:item); 
if(!hf)security_hole(port);
