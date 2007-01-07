#
# This script was written by H D Moore
# 


if(description)
{
    script_id(10993);
    script_version ("$Revision: 1.4 $");
    name["english"] = "IIS ASP.NET Application Trace Enabled";
    script_name(english:name["english"]);


    desc["english"] = "
The ASP.NET web application running in the root
directory of this web server has application
tracing enabled. This would allow an attacker to
view the last 50 web requests made to this server,
including sensitive information like Session ID values
and the physical path to the requested file.

Solution: Set <trace enabled=false> in web.config

Risk factor : High
";

    script_description(english:desc["english"]);

    summary["english"] = "Checks for ASP.NET application tracing";
    script_summary(english:summary["english"]);


    script_category(ACT_ATTACK);

    script_copyright( english:"This script is Copyright (C) 2002 Digital Defense Inc.",
                      francais:"Ce script est Copyright (C) 2002 Digital Defense Inc.");

    family["english"] = "CGI abuses";
    family["francais"] = "Abus de CGI";

    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("find_service.nes", "http_version.nasl");
    script_require_keys("www/iis");
    exit(0);
}


#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port)){ exit(0); }

soc = http_open_socket(port);
if (!soc) exit(0);

req = http_get(item:"/trace.axd", port:port);
send(socket:soc, data:req);
res = http_recv(socket:soc);
if ("Application Trace" >< res)
{
    security_hole(port:port);
}
http_close_socket(soc);
