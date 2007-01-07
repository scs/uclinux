#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10092);
 script_version ("$Revision: 1.21 $");
 name["english"] = "FTP Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the FTP Server type and version by connecting to the server and
processing the buffer received.
The login banner gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.

Solution: Change the login banner to something generic.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "FTP Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;

banner = get_ftp_banner(port: port);

if(banner)
{
 if("NcFTPd" >< banner)set_kb_item(name:"ftp/ncftpd", value:TRUE);
 if(egrep(pattern:".*icrosoft FTP.*",string:banner))set_kb_item(name:"ftp/msftpd", value:TRUE);
 if(egrep(pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner))set_kb_item(name:"ftp/fw1ftpd", value:TRUE);
 if(egrep(pattern:".*Version wu-.*", string:banner))set_kb_item(name:"ftp/wuftpd", value:TRUE);
 if(egrep(pattern:".*xWorks.*", string:banner))set_kb_item(name:"ftp/vxftpd", value:TRUE);
 data = string("Remote FTP server banner :\n", banner);
 security_note(port:port, data:data);
}
