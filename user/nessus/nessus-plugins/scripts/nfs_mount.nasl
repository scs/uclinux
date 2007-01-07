

if(description)
{
 script_id(11356);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-1999-0170", "CVE-1999-0211", "CAN-1999-0554");
 
 name["english"] = "Mountable NFS shares";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin attempts to mount each exported NFS shares,
and issues a red alert if it succeeded.

Some old versions of nfsd do not do the proper checkings when
it comes to NFS access controls, or the remote host may be 
badly configured.


Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for NFS";
 summary["francais"] = "Vérifie les partitions NFS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl", "showmount.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");

mountable = NULL;


list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);


port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
soc = open_priv_sock_udp(dport:port);

port2 = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
soc2 = open_priv_sock_udp(dport:port2);

if(!soc)exit(0);

foreach share (shares)
{
 fid = mount(soc:soc, share:share);
 if(fid)
 {
  content = readdir(soc:soc2, fid:fid);
  mountable += '+ ' + share + '\n' ;
  flag = 0;
  foreach c (content)
  {
   if(flag == 0){
   	mountable += ' + Contents of ' + share + ' : \n';
   	flag = 1;
	}
    mountable += ' - ' + c + '\n'; 
  }
  umount(soc:soc, share:share);
  mountable += '\n\n';
 }
}

close(soc);

if(mountable)
{
 report = string("The following NFS shares could be mounted : \n", 
 		  mountable,
		 "\n",
		 "Make sure the proper access lists are set\n",
		 "Risk factor : High");

 security_hole(port:2049, proto:"udp", data:report);
}		 

