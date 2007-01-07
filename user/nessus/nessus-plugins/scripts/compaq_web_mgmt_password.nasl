# - Written by Christoff Breytenbach <christoff@sensepost.com>
# - Checks only for default password on Compaq Web-based Management
#   Agent on HTTPS (2381/tcp), and not on older versions with login
#   still on HTTP (2301/tcp)
# - Tested on CompaqHTTPServer 4.1, 4.2, 5.0, 5.7

if(description)
{
    script_id(11879);
    script_version ("$Revision: 1.4 $");
    name["english"] = "Compaq Web-based Management Login";
    script_name(english:name["english"]);

    desc["english"] = "
The Compaq Web-based Management Agent active on the remote host is still 
configured with the default administrator password.

This allows an attacker to view sensitive system information, as well as 
reboot the remote system. Furthermore, if an SNMP Agent is configured on 
the remote host it may disclose the SNMP community strings in use, 
allowing an attacker to set device configuration if the 'write' 
community string is uncovered.

To manually test for this bug, you can log into the Compaq web server via
a browser.  The default SSL port is 2381. A typical query would look like:
https://host:2381/ .
You would then enter a User ID of 'Administrator' with a password of 
'Administrator'

Solution: Ensure that all passwords for Compaq Web-based Management Agent accounts 
are set to stronger, less easily guessable, alternatives.
As a further precaution, use the 'IP Restricted Logins' setting to allow 
only authorised IP's to manage this service.

Risk factor : High";

    script_description(english:desc["english"]);

    summary["english"] = "Checks Compaq Web-based Management Agent for Default Administrator Password";

    script_summary(english:summary["english"]);

    script_category(ACT_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2003 SensePost");

    family["english"] = "General";
    script_family(english:family["english"]);
    script_dependencies("find_service.nes", "http_version.nasl");
    script_require_ports("Services/www", 2381);
    exit(0);
}

include("http_func.inc");

# Check starts here

function https_get(port, request)
{
    if(get_port_state(port))
    {
         if(port == 2381)soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
	 else soc = open_sock_tcp(port);
         if(soc)
         {
            send(socket:soc, data:request);
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

debug = 0;

port = get_kb_item("Services/www");
if(!port)port = 2381;

req = string("GET /cpqlogin.htm?RedirectUrl=/&RedirectQueryString= HTTP/1.0\r\n\r\n");

if(debug==1) display(req);

retval = https_get(port:port, request:req);
if(retval == NULL) exit(0);

if(debug == 1) display(retval);

if((retval =~ "HTTP/1.[01] 200") && ("Server: CompaqHTTPServer/" >< retval) && ("Cookie: Compaq" >< retval))
{
    temp1 = strstr(retval, "Set-Cookie: ");
    temp2 = strstr(temp1, ";");
    cookie = temp1 - temp2;
    cookie = str_replace(string:cookie, find:"Set-Cookie", replace:"Cookie");
    req = string("POST /proxy/ssllogin HTTP/1.0\r\n", cookie, 
"\r\nContent-Length: 75\r\n\r\nredirecturl=&redirectquerystring=&user=administrator&password=administrator\r\n");

    if(debug==1) display("\n\n***********************\n\n", req);

    retval = https_get(port:port, request:req);

    if(debug==1) display(retval);

    if("CpqElm-Login: success" >< retval)
    {
        security_hole(port);
    }
}
