#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10908);
 script_version("$Revision: 1.6 $");
 name["english"] = "Users in the Domain Admin group";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the users that are in the domain 
administrators group.

You should make sure that only the proper users are member of this group.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that are in special groups";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : User management";
  
 script_family(english:family["english"]);
 script_dependencies("smb_netusergetgroups.nasl");
 script_require_keys("SMB/Users/enumerated");
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

report = "";
count = 1;
login = get_kb_item(string("SMB/Users/", count));
while(login)
{
 groups = get_kb_item(string("SMB/Users/", count, "/Groups"));
 if(groups)
 {
  grp = string("0x00-0x00-0x02-0x00");
  if(grp >< groups)
  {
  report = report + string(". ", login, "\n");
  }
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}


if(strlen(report))
{
 data = 
 string("The following users are in the domain administrator group :\n", report,
 "\n", "You should make sure that only the proper users are member of this group\n", "Risk factor : Low");
 
 security_note(port:port, data:data);
}
