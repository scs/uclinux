#
# This script was written by Scott Shebby <shebinc@hotmail.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11839);
 script_version ("$Revision$");
 script_cve_id("CAN-2003-0528");
 name["english"] = "Possible RPC Interface compromise";
  
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to log into the remote host as user 'e' with the
password 'asd#321'.

This probably indicates that an attacker exploited one of the
flaws described in MS03-039 with a widely available exploit.


Solution : Re-install this host, as it has been compromised
Risk Factor : Critical";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 'e' user.";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Scott Shebby");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "cifs445.nasl", "smb_login.nasl");
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
login = "e";
pass  = "asd#321";

if(log_in(login:login + string(rand()) , pass:pass + rand(), domain:dom))
  {
  exit(0);
  }
  
  
 if(log_in(login:login, pass:pass, domain:dom))
  {
  security_hole(port);
  } 
