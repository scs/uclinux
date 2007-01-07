#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11561);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(7476);
 name["english"] = "scriptlogic logging share";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an accessible LOGS$ share. 
ScriptLogic creates this share to store the logs, but does
not properly set the permissions on it. As a result, anyone can
use it to read the remote logs.

Solution : Limit access to this share to the backup account
and domain administrator.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to LOG$";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port) port = 139;

#
# Get the listing for \* using a TRANS2_FIND2_FIRST function
#
function readable_share(soc, uid, tid)
{
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x53, 0xFF, 0x53, 0x4D, 0x42, 0x32, 0x00,
		  0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  0x00, 0x00, 0x0F, 0x0F, 0x00, 0x00, 0x00, 0x0A,
		  0x00, 0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x44,
		  0x00, 0x00, 0x00, 0x53, 0x00, 0x01, 0x00, 0x01,
		  0x00, 0x12, 0x00, 0x00, 0x44, 0x20, 0x16, 0x00,
		  0x00, 0x02, 0x0E, 0x00, 0x04, 0x01, 0x00, 0x00,
		  0x00, 0x00, 0x5C, 0x2A, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 13)return("unknown error");
 if(ord(r[9]))
 {
  if((ord(r[11]) == 5) && (ord(r[12])==0))
   { 
    return(FALSE);
   }
  else return("unknown error");
 }
 else return("OK");
}
	

		

function accessible_share(share)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 r = smb_session_request(soc:soc,  remote:name);
 if(!r)return(FALSE);

  #
  # Negociate the protocol
  #
  prot = smb_neg_prot(soc:soc);
  if(!prot)exit(0);


  #
  # Set up our null session 
  #
  r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
  if(!r)return(FALSE);
  # and extract our uid
  uid = session_extract_uid(reply:r);

  access = " - (";
  c = 0;
  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  if(r)
   { 
    tid = tconx_extract_tid(reply:r);
    readable = readable_share(soc:soc, uid:uid, tid:tid);
   
   if(readable){
   	return(TRUE);
	}
    }
  }
  return(FALSE);
}		


#
# Here we go
#		


name = kb_smb_name();
if(!name)exit(0);




login = kb_smb_login();
pass = kb_smb_password();

if(!login)login = "";
if(!pass)pass = "";

dom = kb_smb_domain();


if(!get_port_state(port))exit(0);

if(accessible_share(share:"LOGS$"))security_hole(port);
 
