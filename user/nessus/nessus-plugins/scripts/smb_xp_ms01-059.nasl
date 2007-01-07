#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10835);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(3723);
 script_cve_id("CVE-2001-0876");
 name["english"] = "Unchecked Buffer in XP upnp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

Unchecked Buffer in Universal Plug and Play Can
Lead to System Compromise for Windows XP (Q315000)

By sending a specially-malformed NOTIFY directive,
it would be possible for an attacker to cause code
to run in the context of the UPnP service, which
runs with system privileges on Windows XP.

The UPnP implementations do not adequately
regulate how it performs this operation, and this
gives rise to two different denial-of-service
scenarios. (CVE-2001-0877)

See http://www.microsoft.com/technet/security/bulletin/ms01-059.asp

Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q315000 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access", "SMB/transport");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/Win2K/ServicePack", "SMB/XP/ServicePack");
 
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
#XP only
if(version == "5.1")
{
 sp = get_kb_item("SMB/XP/ServicePack");
 if(sp)exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q315000";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
   security_hole(port);
   exit(0);
 }
}

