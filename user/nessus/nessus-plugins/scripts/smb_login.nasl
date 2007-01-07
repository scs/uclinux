#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10394);
 script_version ("$Revision: 1.54 $");
 script_bugtraq_id(490);
 script_cve_id("CAN-1999-0504", "CAN-1999-0506", "CVE-2000-0222", "CAN-1999-0505", "CAN-2002-1117");
 name["english"] = "SMB log in";
 name["francais"] = "Login SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script attempts to log into the remote host
using several login/password combinations.

Reference : http://support.microsoft.com/support/kb/articles/Q143/4/74.ASP
Reference : http://support.microsoft.com/support/kb/articles/Q246/2/61.ASP

Risk factor : Medium";

 desc["francais"] = "
Ce script tente de se connecter sur l'hote distant
en utilisant plusieurs combinaisons de login/password
usuelles";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Attempts to log into the remote host";
 summary["francais"] = "Essaye de se logguer dans l'hote distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "cifs445.nasl", "find_service.nes", "logins.nasl");
 script_require_keys("SMB/name", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;



function login(lg, pw, dom)
{ 
 _ret = 0;
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

  #
  # Request the session
  # 
  r = smb_session_request(soc:soc,  remote:name);
  if(r)
  {
  #
  # Negociate the protocol
  #
  prot = smb_neg_prot(soc:soc);
  if(prot)
  {
  r = smb_session_setup(soc:soc, login:lg, password:pw, domain:dom, prot:prot);
  if(r)
  {
    uid = session_extract_uid(reply:r);
    r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
    if(r)tid = tconx_extract_tid(reply:r);
    else tid = 0;
    _ret = 1;
    if(!tid)v[count] =  1;
    else v[count] = 2;
    
     if(!g_uid){
     	g_index = count;
     	g_uid = 1;
	}

    # we take the login/pass that gives us access to IPC$		
     if(!g_tid){
     	if(tid)
	{
     	 g_index = count;
	 g_uid = 1;
	 g_tid = 1;
	 }
	}	
   }
  }
  }
  close(soc);
  return(_ret);
}
#----------------------------------------------------------------#
# 			  main()                                 #
#----------------------------------------------------------------#		



name = kb_smb_name();
if(!name)name = "*SMBSERVER";

if(!get_port_state(port))exit(0);

user_login =  string(get_kb_item("SMB/login_filled"));
user_password = string(get_kb_item("SMB/password_filled"));
if(!strlen(user_password))user_password = "";
user_domain = string(get_kb_item("SMB/domain_filled"));

if(strlen(user_domain))
{ 
 smb_domain = user_domain;
}
else
{
 if(!user_domain)user_domain = "";
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 smb_session_request(soc:soc,  remote:name);
 prot = smb_neg_prot(soc:soc);
 close(soc);
 smb_domain = smb_neg_prot_domain(prot:prot);
 if(!smb_domain)smb_domain = string(get_kb_item("SMB/workgroup"));
 if(!smb_domain)smb_domain = NULL;
}


IN_DOMAIN = 2;
IN_HOST   = 1;

l[0] = "administrator";
p[0] = "";
h[0] = 0;
v[0] = 0;

l[1] = "administrator";
p[1] = "administrator";
h[1] = 0;
v[1] = 0;

l[2] = "guest";
p[2] = "";
h[2] = 0;
v[2] = 0;

l[3] = "guest";
p[3] = "guest";
h[3] = 0;
v[3] = 0;



l[4] = "";
p[4] = "whatever";
h[4] = 0;
v[4] = 0;

l[5] = "nessus" + string(rand());
p[5] = "nessus" + string(rand());
h[5] = 0;
v[5] = 0;

l[6] = "";
p[6] = "";
h[6] = 0;
v[6] = 0;

l[7] = "*";
p[7] = "";
h[7] = 0;
v[7] = 0;

l[8] = "pcguest";
p[8] = "";
h[8] = 0;
v[8] = 0;


l[9] = user_login;
p[9] = user_password;
h[9] =  0;
v[9] = 0;

g_index = 0;
g_uid = 0;
g_tid = 0;

IN_HOST = 1;
IN_DOMAIN = 2;

for(count=0;count<10;count=count+1)
{
  if(smb_domain)
  {
  if(login(lg:l[count], pw:p[count], dom:smb_domain))
  	a = IN_DOMAIN;
  else
  	a = 0;
  } 
  else a = 0;
	
  if(login(lg:l[count], pw:p[count], dom:""))
  	b = IN_HOST;
  else
  	b = 0;
  h[count] = a|b;
}

count = 0;
report = string("It was possible to log into the remote host using the following\n",
 "login/password combinations :\n");
 
for(i=0;i<4;i=i+1)
{
 if(v[i])
 {
  report = report + string("       '", l[i], "'", "/'", p[i], "'\n");
  count = count + 1;
 }
}


null_session_level = v[4];
if(!null_session_level)null_session_level = v[6];
if(!null_session_level)null_session_level = v[7];

if(null_session_level > 1)
{info = string("\n",
"It was possible to log into the remote host using a NULL session.\n",
"The concept of a NULL session is to provide a null username and\n",
"a null password, which grants the user the 'guest' access\n\n",
"To prevent null sessions, see MS KB Article Q143474 (NT 4.0) and\n",
"Q246261 (Windows 2000). \n",
"Note that this won't completely disable null sessions, but will \n",
"prevent them from connecting to IPC$\n",
"Please see http://msgs.securepoint.com/cgi-bin/get/nessus-0204/50/1.html\n");


if(count)report = report + info;
else report = info;
}
else
{
 if(null_session_level)
 {
  info = string("\n",
"It was possible to log into the remote host using a NULL session,\n",
"but the IPC$ share could not be connected to, which makes this problem\n",
"rather harmless.\n\n",
"The concept of a NULL session is to provide a null username and\n",
"a null password, which grants the user the 'guest' access\n\n",
"There is no solution to disable null sessions completely\n");


if(count)report = report + info;
else report = info;
 }
}

if(v[5])
{
 set_kb_item(name:"SMB/any_login", value:TRUE);
 info = string("\n",
 "The remote host defaults to guest when a user logs in using an invalid\n",
 "login. For instance, we could log in using the account 'nessus/nessus'\n");

 if(count)report = report + info;
 else if(v[4] || v[6] || v[7])report = report + info;
 else report = info;
}

if(g_uid)
{
 if(strlen(user_login) && h[9] != 0)
 {
  if(v[9])
  {
  l[g_index] = user_login;
  p[g_index] = user_password;
  h[g_index] = h[9];
  }
 }
 
 
 set_kb_item(name:"SMB/login", value:l[g_index]);
 set_kb_item(name:"SMB/password", value:p[g_index]);

 if(h[g_index] & IN_DOMAIN)
 {
  set_kb_item(name:"SMB/domain", value:smb_domain);
 }
 
 if(strlen(user_login))
 {
  if(v[9])
  {
  p[g_index]="****";
  }
 }
 report = report + string("\n\nAll the smb tests will be done as '", l[g_index], "'/'",
 	  p[g_index], "'");
 if(h[g_index] & IN_DOMAIN)
 {
  report = report + string(" in domain ", smb_domain);
 }	
   
 if(l[g_index] == "")
   {
   if(null_session_level > 1)
   	security_hole(port:port, data:report);
   else
   	security_note(port:port, data:report);
   }
 else
   security_hole(port:port, data:report);

}
 
