#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10892);
 script_version("$Revision: 1.9 $");
 name["english"] = "Obtains user information";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script requests informations about each NT user
and stores it in the KB
Risk factor : None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Implements NetUserGetInfo()";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : User management";
  
 script_family(english:family["english"]);
 script_dependencies("smb_scope.nasl",
 		     "netbios_name_get.nasl",
 		     "smb_login.nasl", 
		     "smb_sid2user.nasl",
		     "snmp_lanman_users.nasl");
		     	     
 script_require_keys("SMB/transport",
 		     "SMB/name", 
 		     "SMB/login", 
		     "SMB/password", 
		     "SMB/Users/enumerated",
		     "SMB/test_domain");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

d = get_kb_item("SMB/test_domain");
if(!d)exit(0);

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
dom   = kb_smb_domain();

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

dom = _SamrEnumDomains(	soc:soc, 
		      	uid:uid, 
		      	tid:tid, 
		      	pipe:pipe, 
		      	samrhdl:samrhdl
		      );

if(!dom)exit(0);

sid = SamrDom2Sid(	soc:soc, 
                  	uid:uid, 
		  	tid:tid, 
		  	pipe:pipe, 
		  	samrhdl:samrhdl, 
		  	dom:dom
		 );


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
login = string(get_kb_item(string("SMB/Users/", count)));

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
		  
if(r)_SamrDecodeUserInfo(info:r, count:count, type:"Users");
}
count = count + 1;
login = string(get_kb_item(string("SMB/Users/", count)));
}
