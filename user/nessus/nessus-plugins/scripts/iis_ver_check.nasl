# 
# This script is Copyright (C) 2003 SensePost");
#

if(description)
{
 script_id(11874);
 script_version("$Revision: 1.7 $");
 name["english"] = "IIS Service Pack - 404";
 script_name(english:name["english"]);
 
 desc["english"] = "
The Patch level (Service Pack) of the remote IIS server appears to be lower 
than the current IIS service pack level. As each service pack typically
contains many security patches, the server may be at risk.

Caveat: This test makes assumptions of the remote patch level based on static 
return values (Content-Length) within the IIS Servers 404 error message.
As such, the test can not be totally reliable and should be manually confirmed.


Solution: Ensure that the server is running the latest stable Service Pack 
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "IIS Service Pack Check";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 SensePost");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}


exit(0);


# Check starts here
include("http_func.inc");
include("http_keepalive.inc");



port = get_kb_item("Services/www");
if(!port)port = 80;
if(! get_port_state(port)) exit(0);
r1 = http_get(item:"/nessus" + rand(), port:port);

r  = http_keepalive_send_recv(data:r1, port:port);
if ( r == NULL ) exit(0);
if (!ereg(pattern:"^HTTP.* 404 .*", string:r))exit(0);

v4 = egrep(pattern:"^Server:.*Microsoft-IIS/4\.0", string:r);
v5 = egrep(pattern:"^Server:.*Microsoft-IIS/5\.0", string:r);
cl = egrep(pattern:"^Content-Length", string:r);
ver = string("The remote IIS server *seems* to be ");

if(v4)
{
#	display("IIS4\n");
        if ("102" >< cl)
		{
                ver = ver + string("IIS 4 - Sp0\n");
		#security_hole(port);
       		security_note(port:port, data:ver);
	        exit(0);
		}

	if ("461" >< cl)
		ver = ver + string("Microsoft IIS 4 - SP6\n");
		security_note(port:port, data:ver);
}


if(v5)
{
#        display("IIS5\n");

	if("3243" >< cl)
		ver = ver + string("IIS 5 - Sp0 or Sp1\n");
        if("3252" >< cl)
                ver = ver + string("IIS 5 - Sp2 or Sp2srp1\n");
        if("4040" >< cl)
                ver = ver + string("IIS 5 - Sp3\n");

	if(("3243" >< cl) || ("3252" >< cl) || ("4040" >< cl)){
         		#security_hole(port:port);
         		security_note(port:port, data:ver);
			}

        if("111" >< cl)
		{
		ver = ver + string("Microsoft IIS 5 - SP4\n");
                security_note(port:port, data:ver);
		}
}
	
