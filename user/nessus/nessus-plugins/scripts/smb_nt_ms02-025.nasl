#
# This script was written by Michael Scheidell <scheidell at secnap.net>
# Copyright 2002 SECNAP Network Security, LLC.

#
if(description)
{
 script_id(11143);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2002-0368");
 name["english"] = "Exchange 2000 Exhaust CPU Resources (Q320436)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Malformed Mail Attribute can Cause Exchange 2000 to Exhaust CPU
Resources (Q320436)

Impact of vulnerability: Denial of Service

Affected Software: 

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical

See
http://www.microsoft.com/technet/security/bulletin/ms02-025.asp

(note: requires admin level netbios login account to check)

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q320436, DOS on Exchange 2000";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_W2K.nasl","smtpserver_detect.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion",
		     "SMTP/microsoft_esmtp_5");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

#check for server:
key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = registry_get_sz(key:key, item:item);

if( (value == "LanmanNT") || (value == "ServerNT"))
{

 access = get_kb_item("SMB/registry_full_access");
 if(!access)exit(0);


 #check for Exchange sp3 or above: 6249
 key = "SOFTWARE\Microsoft\Exchange\Setup";
 item = "ServicePackBuild";

 value = registry_get_dword(key:key, item:item);
 if(value)
 {
 if(ereg(string:value, pattern:"6249|[7-9][0-9][0-9][0-9]|6[3-9][0-9][0-9]|62[5-9][0-9]"))exit(0);
 }

 key = "SOFTWARE\Microsoft\Updates\Exchange Server 2000\SP3\Q320436";

 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(25);
 
}

