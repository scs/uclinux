#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11304);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0186", "CVE-2002-0187", "CAN-2002-0186", "CAN-2002-0187");
 script_bugtraq_id(5004, 5005);
 
 
 name["english"] = "Unchecked buffer in SQLXML";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SQLXML. There are flaws in it which may
allow a remote attacker to execute arbitrary code on this host.

Solution : 
 - see http://www.microsoft.com/technet/security/bulletin/ms02-030.asp
 - Install MSSQL Server SP3

Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SQLXML";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "mssql_version.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


version = get_kb_item("mssql/SQLVersion");
if(!version)exit(0);


# SP3 applied - don't know the version number yet
#if(ereg(pattern:"[8-9]\.00\.([8-9][0-9][0-9]|7[67][0-9])", string:version))exit(0);



access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

key = "SYSTEM\CurrentControlSet\Services\SQLXML\Performance";
item = "Library";

value = registry_get_sz(key:key, item:item);
if(!value)exit(0);

# If it's SQL Server Gold, then issue an alert.
if(ereg(pattern:"^8\..*", string:version)) 
{  
 key = "SOFTWARE\Microsoft\Updates\DataAccess\Q321858";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
 exit(0);
}
 




# SQLXML 2.0
if(ereg(pattern:".*sqlxml2\.dll", string:value))
{
 key = "SOFTWARE\Microsoft\Updates\SQLXML 2.0\Q321460";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
 exit(0);
}

# SQLXML 3.0
if(ereg(pattern:".*sqlxml3\.dll", string:value))
{
 key = "SOFTWARE\Microsoft\Updates\SQLXML 3.0\Q320833";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
 exit(0);
}
