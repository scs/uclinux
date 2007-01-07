#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# XXXXX BROKEN
#

if(description)
{
 script_id(10893);
 script_version("$Revision: 1.9 $");
 name["english"] = "Obtains the lists of users aliases";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script requests the list of groups each user belongs
to and stores it in the KB
Risk factor : None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Implements NetUserGetGroups()";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", 
		     "smb_sid2user.nasl",
		     "snmp_lanman_users.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/Users/enumerated");
 script_require_ports(139, 445);
 exit(0);
}


exit(0); # XXXXX broken at this time

include("smb_nt.inc");

port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
if(!soc)exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();


if(!login)login = "";
if(!pass) pass  = "";
if(!domain) domain = "";

name = kb_smb_name();

r = smb_session_request(soc:soc, remote:name);
if(!r){
	#display("smb_session_request failed\n");
	exit(0);
	}
	
prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
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

if(!tid)exit(0);

#display("TID = ", tid, "\n");

pipe = OpenPipeToSamr(	soc:soc, 
		      	uid:uid, 
		      	tid:tid);
		      
#display("PIPE = ", pipe, "\n");

samrhdl = SamrConnect2(	soc:soc, 
		       	uid:uid,
		       	tid:tid, 
		       	pipe:pipe, 
		       	name:name
		      );


dom = _SamrEnumDomains(	soc:soc, 
		      	uid:uid, 
		      	tid:tid, 
		      	pipe:pipe, 
		      	samrhdl:samrhdl
		      );



sid = SamrDom2Sid(	soc:soc, 
                  	uid:uid, 
		  	tid:tid, 
		  	pipe:pipe, 
		  	samrhdl:samrhdl, 
		  	dom:dom
		 );




g_domhdl =
	SamrOpenDomain(	soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			samrhdl:samrhdl,
			sid:sid
		       );		  


bihdl = SamrOpenBuiltin(soc:soc,
			uid:uid,
			tid:tid,
			pipe:pipe,
			samrhdl:samrhdl
			);
	
		
count = 1;
login = string(get_kb_item(string("SMB/Users/", count)));
while(login)
{
rid = SamrLookupNames(  soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			domhdl:g_domhdl,
			name:login
		     );	

if(!rid)
{
 rid = SamrLookupNames(  soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			domhdl:bihdl,
			name:login
		     );	
}



usrhdl = SamrOpenUser(	soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			samrhdl:g_domhdl,
			sid:sid,
	 		rid:rid
		     );
if(!usrhdl)
{
 #display("Hu ho. Using bihdl\n");
 
 usrhdl = SamrOpenUser(	soc:soc, 
			uid:uid, 
			tid:tid, 
			pipe:pipe, 
			samhdl:bihdl,
			sid:sid,
	 		rid:rid
		     );
		     
		     
}			

		     

rids = SamrQueryUserAliases(soc:soc, 
	     	  	uid:uid,
		  	tid:tid,
		  	pipe:pipe,
		  	usrhdl:bihdl, 
			sid:sid,
			rid:rid);	
			
 
if(rids)
 {
  name = string("SMB/Users/", count, "/LocalGroups");
  set_kb_item(name:name, value:rids);
  #display(rids);
 }	     

 count = count + 1;
 login = string(get_kb_item(string("SMB/Users/", count)));
}		 
		  
