#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10907);
 script_version("$Revision: 1.4 $");
 name["english"] = "Guest belongs to a group";

 script_name(english:name["english"]);
 
 desc["english"] = "
The guest user belongs to groups other than 
guest users or domain guests.

As guest should not have any privilege, you should
fix this.

Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the groups of guest";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("smb_netusergetgroups.nasl", 
 		     "smb_netusergetaliases.nasl");
 script_require_keys("SMB/Users/2");
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;


aliases = get_kb_item("SMB/Users/2/LocalGroups");
groups  = get_kb_item("SMB/Users/2/Groups");

if(groups)
{
 groups = groups - "0x00-0x00-0x02-0x01";
 if(strlen(groups) > 5)
 {
  security_warning(port);
  exit(0);
 }
}


if(aliases)
{
 groups = groups - "0x00-0x00-0x02-0x22";
 if(strlen(groups) > 5)
 {
  security_warning(port);
 }
}
