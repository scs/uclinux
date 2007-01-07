# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10900);
 script_version("$Revision: 1.4 $");
 name["english"] = "Users information : Passwords never expires";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the users whose
password never expires.

Passwords should have a limited lifetime.

Solution : disable the 'password never expires' checkbox for these users
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
 p = get_kb_item(string("SMB/Users/", count, "/Info/PassMustChange"));
 if(p)
 {
  exp = "0x7f-0xff-0xff-0xff-0xff-0xff-0xff-0xff";
  if(p == exp){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}

if(logins)
{
 rep = string("The following accounts have passwords which never expire :\n\n",
  logins,
  "\n\nPassword should have a limited lifetime\n",
  "Solution : disable password non-expiry\n",
  "Risk factor : Medium");
 security_warning(port:port, data:rep);
}
