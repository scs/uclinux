#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10404);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CAN-1999-0504", "CAN-1999-0506");
 name["english"] = "SMB log in as users";
 name["francais"] = "Login SMB avec les noms d'utilisateurs";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script attempts to log into the remote host
using several login/password combinations.

It may be dangerous due to the fact that it may
lock accounts out if your security policy is ultra-tight.

Risk factor : Medium";

 desc["francais"] = "
Ce script tente de se connecter sur l'hote distant
en utilisant plusieurs combinaisons de login/password
usuelles

Il peut etre dangereux dans le sens où il risque de verouiller
des comptes dans des environnements où la politique de sécurité
est très stricte
";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Attempts to log into the remote host";
 summary["francais"] = "Essaye de se logguer dans l'hote distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_sid2user.nasl",
		     "smb_sid2localuser.nasl",
 		     "snmp_lanman_users.nasl");
 script_require_keys("SMB/name");
 script_require_ports(139, 445);
 script_timeout(0);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;

if(get_kb_item("SMB/any_login"))exit(0);


function log_in(login, pass, domain)
{

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
  r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
  close(soc);
  if(r)return(TRUE);
  else return(FALSE);
  }
 }
 close(soc);
 return(FALSE);
}

#----------------------------------------------------------------#
# 			  main()                                 #
#----------------------------------------------------------------#		


name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

dom = kb_smb_domain();

finished = 0;
count = 1;
vuln = "";

okcount = 1;
login = kb_smb_login();
pass  = kb_smb_password();

set_kb_item(name:string("SMB/ValidUsers/0/Login"), value:login);
set_kb_item(name:string("SMB/ValidUsers/0/Password"), value:pass);

current = "SMB/Users";


while(!finished)
{
 login = string(get_kb_item(string(current, count)));
 if(!login){
  	if(current == "SMB/LocalUsers/") 
	  {
   		finished = 1;
	  }
	else {
	  current = "SMB/LocalUsers/";
	  count = 0;
	}
 }
 else
 {
  if(log_in(login:login, pass:"", domain:dom))
  {
   vuln = vuln + string(". User '", login, "' has NO password !\n");
   a = string("SMB/ValidUsers/", okcount, "/Login");
   b = string("SMB/ValidUsers/", okcount, "/Password");
   set_kb_item(name:a, value:login);
   set_kb_item(name:b, value:"");
   okcount = okcount + 1;
  }
  else if(log_in(login:login, pass:login, domain:dom))
  {
   vuln = vuln + string(". The password of '", login, "' is '", login, "' !\n");
   a = string("SMB/ValidUsers/", okcount, "/Login");
   b = string("SMB/ValidUsers/", okcount, "/Password");
   set_kb_item(name:a, value:login);
   set_kb_item(name:b, value:login);
   okcount = okcount + 1;
  }
 }
 count = count + 1;
}

if(strlen(vuln))
{
 security_hole(port:port, data:vuln);
}
