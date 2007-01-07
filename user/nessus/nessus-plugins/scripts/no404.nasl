
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# - rewritten in parts by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10386);
 script_version ("$Revision: 1.50 $");

 name["english"] = "No 404 check";
 name["francais"] = "No 404 check";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote  web servers is [mis]configured in that it
does not return '404 Not Found' error codes when
a non-existent file is requested, perhaps returning
a site map or search page instead.

Nessus enabled some counter measures for that, however
they might be insufficient. If a great number of security
holes are produced for this port, they might not all be accurate";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the remote webserver issues 404 errors";
 summary["francais"] = "Vérifie que le serveur web distant sort des erreurs 404";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_login.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function check(url, port)
{
    req = http_get(item:url, port:port);
    result = http_keepalive_send_recv(data:req, port:port);
    if(result == NULL)exit(0);
    return(result);
}

function find_err_msg(buffer)
{
    cmsg = 0;
    for (cmsg = 0; errmsg[cmsg]; cmsg = cmsg + 1)
    {
        cpat = errmsg[cmsg];
        if (egrep(pattern:cpat, string:buffer, icase:TRUE))
        {
            #if (debug) display("'",cpat, "' found in '", buffer, "'\n");
            return(cpat);
        }
    }

    return (0);
}

# build list of test urls

basename="404";
while ("404" >< basename) basename=string("/NessusTest", rand());

badurl[0] = string(basename, ".html");
badurl[1] = string(basename, ".cgi");
badurl[2] = string(basename, ".sh");
badurl[3] = string(basename, ".pl");
badurl[4] = string(basename, ".inc");
badurl[5] = string(basename, ".shtml");
badurl[6] = string(basename, ".asp");
badurl[7] = string(basename, ".php");
badurl[8] = string(basename, ".php3");
badurl[9] = string(basename, ".cfm");

badurl[10] = string("/cgi-bin", basename, ".html");
badurl[11] = string("/cgi-bin", basename, ".cgi");
badurl[12] = string("/cgi-bin", basename, ".sh");
badurl[13] = string("/cgi-bin", basename, ".pl");
badurl[14] = string("/cgi-bin", basename, ".inc");
badurl[15] = string("/cgi-bin", basename, ".shtml");
badurl[16] = string("/cgi-bin", basename, ".php");
badurl[17] = string("/cgi-bin", basename, ".php3");
badurl[18] = string("/cgi-bin", basename, ".cfm");

errmsg[0] = "not found";
errmsg[1] = "404";
errmsg[2] = "error has occurred";
errmsg[3] = "FireWall-1 message";
errmsg[4] = "Reload acp_userinfo database";
errmsg[5] = "IMail Server Web Messaging";
errmsg[6] = "HP Web JetAdmin";
errmsg[7] = "Error processing SSI file";
errmsg[8] = "ExtendNet DX Configuration";
errmsg[9] = "Unable to complete your request due to added security features";
errmsg[10] = "Client Authentication Remote Service</font>";
errmsg[11] = "Bad Request";
errmsg[12] = "Webmin server";
errmsg[13] = "Management Console";	
errmsg[14] = "TYPE=password";	# As in "<input type=password>"
errmsg[15] = "The userid or password that was specified is not valid.";  # Tivoli server administrator   
errmsg[16] = "Access Failed";
errmsg[17] = "Please identify yourself:";
errmsg[18] = "forcelogon.htm";
errmsg[19] = "encountered an error while publishing this resource";
errmsg[20] = "No web site is configured at this address";
errmsg[21] = 'name=qt id="search" size=40 value=" "';
errmsg[22] = "PHP Fatal error:  Unable to open";

debug = 0;

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

for (c = 0; badurl[c]; c = c + 1)
{
    url = badurl[c];
    
    if(debug) display("Checking URL ", url, "\n");
    ret = check(url:url, port:port);
  
    if (!(ret == 0))
    {

        raw_http_line = egrep(pattern:"^HTTP/", string:ret);
	found = string("www/no404/", port);
        # check for a 200 OK
        if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:raw_http_line))
        {
             # look for common "not found": indications
             not_found = find_err_msg(buffer:ret);
             if (not_found != 0)
             {
                
                set_kb_item(name:found, value:string(not_found));
                security_note(port);
                
                if(debug) display("200: Using string: ", not_found, "\n");
                exit(0);              
             } else {
                
                # try to match the title
                title = egrep(pattern:"<title", string:ret, icase:TRUE);
                if (title)
                {
                    title = ereg_replace(string:title, pattern:".*<title>(.*)</title>.*", replace:"\1", icase:TRUE);
                    if (title)
                    {
                        if(debug) display("using string from title: ", title, "\n");
                        set_kb_item(name:found, value:title);
                        security_note(port);
                        exit(0);
                    }
                }
                
                # try to match the body tag
                body = egrep(pattern:"<body", string:ret, icase:TRUE);
                if (body)
                {
                    body = ereg_replace(string:body, pattern:"<body(.*)>", replace:"\1", icase:TRUE);
                    if (body)
                    {
                        if(debug) display("using string from body: ", body, "\n");
                        set_kb_item(name:found, value:body);
                        security_note(port);
                        exit(0);
                    }
                }
                
                # get mad and give up
                if(debug)display("argh! could not find something to match against.\n");
                if(debug)display("[response]", ret, "\n");
		msg = "
This web server is [mis]configured in that it
does not return '404 Not Found' error codes when
a non-existent file is requested, perhaps returning
a site map or search page or authentication page instead.

Unfortunately, we were unable to find a way to recognize this page,
so some CGI-related checks have been disabled.

To work around this issue, please contact the Nessus team.";
		security_note(port: port, data: msg);
		found = string("www/no404/", port);
		set_kb_item(name:found, value:"HTTP");
                exit(0);
                
             }
        }
        
        # check for a 302 Moved Temporarily or 301 Move Permanently
        if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 30[12] ", string:raw_http_line))
        {
             # put the location field as no404 msg
             found = string("www/no404/", port);
	     loc = egrep(string: ret, pattern: "^Location:");
             set_kb_item(name:found, value:loc);
             
             security_note(port);
             if(debug) display("302: Using ", raw_http_line, "\n");
             exit(0);                 
        }
        
    } else {
        if(debug) display("An error occurred when trying to request: ", url, "\n");
    }
}



