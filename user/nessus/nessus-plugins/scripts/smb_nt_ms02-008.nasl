#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10866);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(3699);
 script_cve_id("CVE-2002-0057");
 name["english"] = "XML Core Services patch (Q318203)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
XMLHTTP Control Can Allow Access to Local Files.

A flaw exists in how the XMLHTTP control applies IE security zone
settings to a redirected data stream returned in response to a
request for data from a web site. A vulnerability results because
an attacker could seek to exploit this flaw and specify a data
source that is on the user's local system. The attacker could
then use this to return information from the local system to the
attacker's web site. 

Impact of vulnerability: Attacker can read files on client system.

Affected Software: 

Microsoft XML Core Services versions 2.6, 3.0, and 4.0.
An affected version of Microsoft XML Core Services also
ships as part of the following products: 

Microsoft Windows XP 
Microsoft Internet Explorer 6.0 
Microsoft SQL Server 2000 

(note: versions earlier than 2.6 are not affected
files affected include msxml[2-4].dll and are found
in the system32 directory. This might be false
positive if you have earlier version)

See http://www.microsoft.com/technet/security/bulletin/ms02-008.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the XML Core Services patch Q318203 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_registry_full_access.nasl",
 		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access", "SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/XP/ServicePack");
 exit(0);
}

include("smb_nt.inc");


port = get_kb_item("SMB/transport");
if(!port)port = 139;

version = get_kb_item("SMB/WindowsVersion");

if(version)
{
  access = get_kb_item("SMB/registry_access");
  if(!access)exit(0);

   # Win2003 not vulnerable.
  if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);
  
  if("5.1" >< version)
  {
    sp = get_kb_item("SMB/WinXP/ServicePack");
    if( sp && ereg(pattern:"Service Pack [1-9]", string:sp))exit(0);
  }
  
# need full registry access for Win2k and XP
  if(egrep(pattern:"^5.",string:version))
  {
    access = get_kb_item("SMB/registry_full_access");
    if(!access)exit(0);
  } 

 key = "SOFTWARE\Microsoft\Updates\DataAccess\Q318203";
 item = "Description";
 value = string(registry_get_sz(key:key, item:item));

 if(!value)
 {
   security_hole(port);
   exit(0);
 }
}

