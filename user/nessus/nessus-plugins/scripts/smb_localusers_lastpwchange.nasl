# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10914);
 script_version("$Revision: 1.2 $");
 name["english"] = "Local users information : Never changed password";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the local users that
never changed their passwords.


Risk factor : Serious";



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
 p = get_kb_item(string("SMB/LocalUsers/", count, "/Info/PassLastSet"));
 if(p)
 {
  nvr = "0x00-0x00-0x00-0x00-0x00-0x00-0x00-0x00";
  if(p == nvr){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/LocalUsers/", count));
}

if(logins)
{
 rep = string("The following local accounts have never changed their password :\n\n",
  logins,
  "\n\nTo minimize the risk of break-in, users should\n",
  "change their password regularly");
 security_warning(port:port, data:rep);
}
