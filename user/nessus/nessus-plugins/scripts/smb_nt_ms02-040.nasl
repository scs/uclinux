#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
# MS03-030 supercedes MS02-040
#
# Note: The fix for this issue will be included in MDAC 2.5 Service Pack 5 and in MDAC 2.7 Service Pack 2. 
# The script should be update when the service pack is released.
#
# MS03-030 Prerequisites:
# You must be running one of the following versions of MDAC: 
# MDAC 2.5 Service Pack 2
# MDAC 2.5 Service Pack 3 
# MDAC 2.6 Service Pack 2
# MDAC 2.7 RTM
# MDAC 2.7 Service Pack 1
# Other versions of MDAC are not affected by this vulnerability.  
#
# MS02-040 Fixed in :
#	- MDAC 2.5 SP3
#	- MDAC 2.6 SP3
#	- MDAC 2.7 SP1
#
if(description)
{
 script_id(11301);
 script_version("$Revision: 1.9 $");
 
 script_bugtraq_id(5372);
 script_cve_id("CVE-2002-0695", "CVE-2003-0353", "2002-0695", "CAN-2003-0353");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0010");
 name["english"] = "Unchecked buffer in MDAC Function";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Microsoft Data Access Component (MDAC) server
is vulnerable to a flaw which could allow an attacker to
execute arbitrary code on this host, provided he can
load and execute a database query on this server.

Impact of vulnerability: Elevation of Privilege 

Affected Software: 

MDAC version 2.5 Service Pack 2
MDAC version 2.5 Service Pack 3
MDAC version 2.6 Service Pack 2
MDAC version 2.7 RTM
MDAC version 2.7 Service Pack 1

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Moderate

See
http://www.microsoft.com/technet/security/bulletin/ms
http://www.microsoft.com/security/security_bulletins/ms03-033.asp
http://www.microsoft.com/technet/security/bulletin/ms02-040.asp

Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of MDAC";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

key = "SOFTWARE\Microsoft\DataAccess";
item = "Version";
version = registry_get_sz(key:key, item:item);
if(!version)exit(0);



if(ereg(pattern:"2\.7.*", string:version))
{
  #MS02-040
  #if(ereg(pattern:"2\.7[1-9].*", string:version))exit(0); # SP1 applied
  #key = "SOFTWARE\Microsoft\Updates\DataAccess\Q323263";
  
  #MS03-030, NO 2.7 SP2 right now.
  key = "SOFTWARE\Microsoft\Updates\DataAccess\Q823718";
  item = "Description";
  hf = registry_get_sz(key:key, item:item);
  if(!hf)security_warning(port);
}
else if(ereg(pattern:"2\.6.*", string:version))
{
 #MS02-040
 #if(ereg(pattern:"2\.6[3-9].*", string:version))exit(0); # SP3 applied
 #key = "SOFTWARE\Microsoft\Updates\DataAccess\Q323266";

 #MS03-030, 2.6 SP3 has no problem
 if(ereg(pattern:"2\.6[3-9].*", string:version))exit(0); # SP3 applied
 key = "SOFTWARE\Microsoft\Updates\DataAccess\Q823718";
 item = "Description";
 hf = registry_get_sz(key:key, item:item);
 if(!hf)security_warning(port);
}
else if(ereg(pattern:"2\.5.*", string:version))
{
 #MS-2-040
 #if(ereg(pattern:"2\.5[3-9].*", string:version))exit(0); # SP3 applied
 #key = "SOFTWARE\Microsoft\Updates\DataAccess\Q323264";

 #MS03-030, No 2.5 SP5 yet, and seems 2.5 SP4 will not include it.
 key = "SOFTWARE\Microsoft\Updates\DataAccess\Q823718";
 item = "Description";
 hf = registry_get_sz(key:key, item:item);
 if(!hf)security_warning(port);
}
