# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10897);
 script_version("$Revision: 1.4 $");
 name["english"] = "Users information : disabled accounts";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the disabled
accounts.

Permanently disabled accounts should be suppressed.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that have special privileges";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
script_dependencies("smb_netusergetinfo.nasl");
 
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

logins = "";
count = 1;
login = get_kb_item(string("SMB/Users/", count));
while(login)
{
 acb = get_kb_item(string("SMB/Users/", count, "/Info/ACB"));
 if(acb)
 {
  if(acb & 0x0001){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}

if(logins)
{
 rep = string("The following accounts are disabled :\n\n",
  logins,
  "\n\nTo minimize the risk of break-in, permanently disabled accounts\n",
  "should be deleted\n",
  "Risk factor : Low");
 security_note(port:port, data:rep);
}
