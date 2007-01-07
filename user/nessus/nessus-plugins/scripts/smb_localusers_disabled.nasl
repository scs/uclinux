# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10913);
 script_version("$Revision: 1.2 $");
 name["english"] = "Local users information : disabled accounts";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the disabled
local accounts.

Permanently disabled accounts should be suppressed.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the local users that have special privileges";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
script_dependencies("smb_netusergetinfo_local.nasl");
 
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

logins = "";
count = 1;
login = get_kb_item(string("SMB/LocalUsers/", count));
while(login)
{
 acb = get_kb_item(string("SMB/LocalUsers/", count, "/Info/ACB"));
 if(acb)
 {
  if(acb & 0x0001){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/LocalUsers/", count));
}

if(logins)
{
 rep = string("The following local accounts are disabled :\n\n",
  logins,
  "\n\nTo minimize the risk of break-in, permanently disabled accounts\n",
  "should be deleted\n",
  "Risk factor : Low");
 security_note(port:port, data:rep);
}
