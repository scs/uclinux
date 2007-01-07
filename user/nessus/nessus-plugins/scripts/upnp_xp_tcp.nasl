#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11765);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "scan for UPNP/Tcp hosts";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Microsoft UPnP TCP helper.

If the tested network is not a home network, you should disable
this service.

Solution : Delete the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\SSDPSRV 
and reboot the remote host

Risk Factor : Low";


 script_description(english:desc["english"]);

 summary["english"] = "UPNP/tcp scan";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(5000);
 exit(0);
}


if(get_port_state(5000))
{
 soc = open_sock_tcp(5000);
 if( !soc)exit(0);
 send(socket:soc, data:'\r\n\r\n');
 r = recv_line(socket:soc, length:4096);
 if("HTTP/1.1 400 Bad Request" >< r) 
 {
 	security_warning(5000);
 }
}
