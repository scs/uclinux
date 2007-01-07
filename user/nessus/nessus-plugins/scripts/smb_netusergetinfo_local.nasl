#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10910);
 script_version("$Revision: 1.10 $");
 name["english"] = "Obtains local user information";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script requests informations about each local NT user
and stores it in the KB
Risk factor : None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Implements NetUserGetInfo()";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : User management";
  
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", 
		     "smb_sid2localuser.nasl",
		     "smb_host2sid.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/LocalUsers/enumerated", "SMB/host_sid");
 script_require_ports(139, 445);
 exit(0);
}

#---------------------------------------------------------#
# hexstr() to raw_string() conversion			  #
#---------------------------------------------------------#

function hexsid_to_rawsid(s)
{
 local_var i, j, ret;
 
 for(i=0;i<strlen(s);i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
  	j = int(s[i]);
  else
  	j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
  	j += int(s[i+1]);
  else
  	j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}




include("smb_nt.inc");

port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
if(!soc)exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
dom   = kb_smb_domain();


# we need the SID of the host
sidx = get_kb_item("SMB/host_sid_hex");
if(!sidx)exit(0);


# conversion string -> hex
sid = hexsid_to_rawsid(s:sidx);







if(!login)login = "";
if(!pass) pass = "";
if(!dom) dom = "";

name = kb_smb_name();

r = smb_session_request(soc:soc, remote:name);
if(!r){
	#display("smb_session_request failed\n");
	exit(0);
	}
	
prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);	
r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
if(!r){
	#display("Session setup failed\n");
	exit(0);
	}

uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# extract our tree id
tid = tconx_extract_tid(reply:r);


#display("TID = ", tid, "\n");

pipe = OpenPipeToSamr(	soc:soc, 
		      	uid:uid, 
		      	tid:tid);
		      
#display("PIPE = ", pipe, "\n");
if(!pipe)exit(0);

samrhdl = SamrConnect2(	soc:soc, 
		       	uid:uid,
		       	tid:tid, 
		       	pipe:pipe, 
		       	name:name
		      );

if(!samrhdl)exit(0);

samrhdl =
	SamrOpenDomain(	soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			samrhdl:samrhdl,
			sid:sid
		       );		  
if(!samrhdl)exit(0);

count = 1;
login = string(get_kb_item(string("SMB/LocalUsers/", count)));
while(login)
{
rid = SamrLookupNames(  soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			domhdl:samrhdl,
			name:login
		     );	


usrhdl = SamrOpenUser(	soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			samrhdl:samrhdl,
	 		rid:rid
		     );
			
if(usrhdl)
{			
r = SamrQueryUserInfo(	soc:soc, 
	     	  	uid:uid,
		  	tid:tid,
		  	pipe:pipe,
		  	usrhdl:usrhdl
		  );
		  
if(r)_SamrDecodeUserInfo(info:r, count:count, type:"LocalUsers");
}
count = count + 1;
login = string(get_kb_item(string("SMB/LocalUsers/", count)));
}
