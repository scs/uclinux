#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11454);

 name["english"] = "SMB log in with W32/Deloder passwords";
 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
W32/Deloder is a worm that contains a list of built-in administrator
passwords and tries to connect to a remote share by using them.

This plugin attempts to log in using the passwords contained
in this worm

Solution : Change your administrator password to a strong one
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote host";
 summary["francais"] = "Essaye de se logguer dans l'hote distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
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

login = string(get_kb_item("SMB/LocalUsers/0"));
if(!login)login = "administrator";

passwords = make_list("", "0", "000000", "00000000", "007", "1",
		      "110", "111", "111111", "11111111", "12",
		      "121212", "123", "123123", "1234", "12345",
		      "123456", "1234567", "12345678", "123456789",
		      "1234qwer", "123abc", "123asd", "123qwe",
		      "2002", "2003", "2600", "54321", "654321", 
		      "88888888", "Admin", "Internet", "Login",
		      "Password", "a", "aaa", "abc", "abc123", "abcd",
		      "admin", "admin123", "administrator", "alpha",
		      "asdf", "computer", "database", "enable", "foobar",
		      "god", "godblessyou", "home", "ihavenopass", "login",
		      "love", "mypass", "mypass123", "mypc", "mypc123",
		      "oracle", "owner", "pass", "passwd", "password",
		      "pat", "patrick", "pc", "pw", "pw123", "pwd", "qwer",
		      "root", "secret", "server", "sex", "super", "sybase",
		      "temp", "temp123", "test", "test123", "win", "xp",
		      "xxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		      "yxcv", "zxcv");
		      
		      
foreach p (passwords)
{
 if(log_in(login:login, pass:p, domain:dom))
 {
  report = "
The account '" + login + "'/'" + p + "' is valid. 
The worm W32/Deloder may use it to break into the remote host
and upload infected data in the remote shares

See also : CERT advisory CA-2003-08
Solution : Change your administrator password to a stronger one
Risk factor : High";

  security_hole(port:port, data:report);
  exit(0);
 }
}
