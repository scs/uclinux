#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10396);
 script_version ("$Revision: 1.44 $");
 script_bugtraq_id(8026);
 script_cve_id("CAN-1999-0519", "CAN-1999-0520");
 name["english"] = "SMB shares access";
 name["francais"] = "Accès aux shares SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script checks if we can access various
NetBios shares

Risk factor : High";

 desc["francais"] = "
Ce script se connect à l'hote distant
et dresse la liste des shares accessible
à distance";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Gets the list of remote accessible shares";
 summary["francais"] = "Obtention de la liste des shares accessibles distantes";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_enum_shares.nasl",
		     "smb_login_as_users.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
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
	
#
# Create a directory on the remote host to determine if the
# share is writeable or not
#

function writeable_share(soc, tid, uid)
{
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 

 randstr = string(rand()%10, rand()%10, rand()%10, rand()%10);
 req = raw_string(0x00, 0x00,
 		  0x00, 0x30, 0xFF, 0x53, 0x4D, 0x42, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  0x00, 0x00, 0x00, 0x0D, 0x00, 0x04, 0x5C) +
		 "Nessus" + randstr + raw_string(0x00);

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:1024);
 
 if(ord(r[9]))
 {
  if((ord(r[11]) == 5) && (ord(r[12])==0))
   { 
    return(FALSE);
   }
  else return("unknown error");
 }
 else 
 {
 # The dir was created. We delete it before we return
 req = raw_string(0x00, 0x00,
 		  0x00, 0x30, 0xFF, 0x53, 0x4D, 0x42, 0x01, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  0x00, 0x00, 0x00, 0x0D, 0x00, 0x04, 0x5C) +
		 "Nessus" + randstr + raw_string(0x00);

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:8192);
 return("OK");
 }
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
   	if(readable == "unknown error")access = access + "readable?";
	else access = access + "readable";
	c = c + 1;
	}
    
   
   
    
   writeable = writeable_share(soc:soc, uid:uid, tid:tid);
   if(writeable){
   	if(access)access = access + ", ";
	c = c + 1;
	if(writeable == "unknown error")access = access + "writeable?";
	else access = access + "writeable";
	}
   
   access = access + ")";
   
   if( readable )
   {
    dirs = FindFirst2(socket:soc, uid:uid, tid:tid);
    if(!isnull(dirs))
    {
    access += '\n  + Content of this share :\n';
    foreach file (dirs)
    {
     access += '   - ' + file + '\n';
    }
    }
   }
   close(soc);
   if(c)return(access);
   else return(FALSE);
  }
  else close(soc);
  }
  return(FALSE);
 }		


#
# Here we go
#		


name = kb_smb_name();
if(!name)exit(0);




login = kb_smb_login();
pass =  kb_smb_password();

if(!login)login = "";
if(!pass)pass = "";

dom = kb_smb_domain();


if(!get_port_state(port))exit(0);

count = 1;

shares = get_kb_list("SMB/shares");
if(isnull(shares))shares = make_list();

shares = make_list(shares);
addme = make_list();

foreach s (make_list("WINNT$", "C$", "D$", "ADMIN$", "ROOT"))
{
  flag = 0;
  foreach t (shares)
  {
    if ( t == s ) {
      	flag = 1;
	break;
    }
  }

  if ( flag == 0 ) addme = make_list(addme, s);
}


shares = make_list(shares, addme);


run = 1;


while(1)
{
vuln = "";
accs = "";


foreach share (shares) 
{
  accs = accessible_share(share:share);
  if(accs)
  {
   vuln += string("- ", share, " ", accs, "\n");
  }
}

if(strlen(vuln) > 0)
 {
  kb_item = string("SMB/accessible_shares/", count);
  set_kb_item(name:kb_item, value:egrep(pattern:"^-", string:vuln));
  
  if(!strlen(login))t = "using a NULL session ";
  else t = string("as ", login);
  
  rep = string("The following shares can be accessed ", t, " :\n\n")
   	+ vuln +
	string("\n\nSolution : To restrict their access under WindowsNT, open the explorer, do a right click on each,\ngo to the 'sharing' tab, and click on 'permissions'\nRisk factor : High");
  security_hole(port:port, data:rep);
 }

if(get_kb_item("SMB/any_login"))exit(0);

a = string("SMB/ValidUsers/", count, "/Login");
b = string("SMB/ValidUsers/", count, "/Password");
login = string(get_kb_item(a));
pass  = string(get_kb_item(b));
count = count + 1;
if(!strlen(login) && !strlen(pass))exit(0);
}
