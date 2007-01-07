# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10899);
 script_version("$Revision: 1.5 $");
 name["english"] = "Users information : User has never logged in";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the users that
have never logged in.


Unused accounts are very helpful to attackers.

Solution : delete those unused accounts
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that never logged in";

 
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
 p = get_kb_item(string("SMB/Users/", count, "/Info/LogonTime"));
 if(p)
 { 
  exp = "0x00-0x00-0x00-0x00-0x00-0x00-0x00-0x00";
  if(p == exp){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}

if(logins)
{
 rep = string("The following accounts have never logged in :\n\n",
  logins,
  "\n\nUnused accounts are very helpful to hacker\n",
  "Solution : suppress these accounts\n",
  "Risk factor : Medium");
 security_warning(port:port, data:rep);
}
