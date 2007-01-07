#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
#
# Also supercedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015
#
# Other CVEs: CVE-2001-1325  CVE-2001-0149 CVE-2001-0727
#	      CVE-2001-0875  CVE-2001-0339 CVE-2001-0002
#	      CAN-2002-0190  CVE-2002-0026 CAN-2003-1326
#	      CVE-2002-0027  CVE-2002-0022 CAN-2003-1328
#	      CAN-2002-1262  CAN-2002-0193 CAN-1999-1016
#             CVE-2003-0344  CAN-2003-0233 CAN-2003-0309
#	      
# 

if(description)
{
 script_id(10861);
 script_version("$Revision: 1.28 $");
 script_bugtraq_id(3578, 8556, 8565);
 script_cve_id("CAN-2003-0838", "CAN-2003-0809", 
 	       "CAN-2003-0530", "CAN-2003-0531", 
	       "CAN-2003-0113", "CAN-2003-0114", 
	       "CAN-2003-0115", "CAN-2003-0116");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0018");
 name["english"] = "IE 5.01 5.5 6.0 Cumulative patch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The 4 June 2003 Cumulative Patch for IE is
not applied on the remote host.

Impact of vulnerability: Run code of attacker's choice. 

Recommendation: Customers using IE should install the patch immediately. 

Affected Software: 

Microsoft Internet Explorer 5.01 (SP3 required to install)
Microsoft Internet Explorer 5.5 (SP2 required to install)
Microsoft Internet Explorer 6.0 

NOTE: Might require full registry access on win2k, xp and Server 2003

Supersedes MS01-055, MS01-058, MS02-005, MS02-066, MS02-068, MS03-004, MS03-014, 
MS03-015, MS03-020, MS03-032 and others

See http://www.microsoft.com/technet/security/bulletin/ms03-040.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q828750 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_full_access.nasl",
 		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access");
 script_require_ports(139, 445);
 script_require_keys("SMB/WindowsVersion");
 exit(0);
}

include("smb_nt.inc");

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;


version = get_kb_item("SMB/WindowsVersion");

if(version)
{
 key = "SOFTWARE\Microsoft\Internet Explorer\Version Vector";
 item = "IE";
 value = string(registry_get_sz(key:key, item:item));

 if(!value)
 {
   exit(0);
 }

 report = string("We were able to determine that you are running IE Version ",value);
 
 key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
 item = "MinorVersion";
 minorversion = string(registry_get_sz(key:key, item:item));

 if(minorversion)
    report = report + string("\nwith these IE Hotfixes installed:",minorversion);


 missing = NULL;
 if("Q828750" >!< minorversion)missing += "Q828750 (MS03-040) ";
# if("822925" >!< minorversion) missing += "Q822925 (MS03-032) ";
# if("Q818529" >!< minorversion)missing += "Q818529 (MS03-020) ";
# if("Q813489" >!< minorversion)missing += "Q813489 (MS03-015) ";
# if("Q330994" >!< minorversion)missing += "Q330994 (MS03-014) ";
  
 if( missing )
   {
    report = report + string("\n
But is missing security update(s) ", missing, "
Recommendation: Customers using Microsoft IE  should install
this patch immediately. 

Impact of vulnerability: Run code of attacker's choice. 

See http://www.microsoft.com/technet/security/bulletin/ms03-040.asp 

Supersedes MS01-055, MS01-058, MS02-005, MS02-066, MS02-068, MS03-004, MS03-014, 
MS03-015, MS03-020, MS03-032 and others

Risk factor : High");

   security_hole(port:port, data:report);
  }
 else
   security_note(port:port, data:report);
}

