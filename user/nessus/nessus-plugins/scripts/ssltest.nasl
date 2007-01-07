if(description)
{
 script_id(11875);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2003-0543", "CAN-2003-0544", "CAN-2003-0545");
 script_bugtraq_id(8732);

 name["english"] = "OpenSSL overflow via invalid certificate passing";

 script_name(english:name["english"]);

 desc["english"] = "The remote host seem to be running a version of OpenSSL which is older than 0.9.6k or 0.9.7c. 

There is a heap corruption bug in this version which might be exploited by an
attacker to gain a shell on this host.

Solution : If you are running OpenSSL, Upgrade to version 0.9.6k or 0.9.7c or newer
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for the behavior of SSL";

 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");

 exit(0);
}



# start script code


function hex2raw(s)
{
 local_var i, j, ret;

 for(i=0;i<strlen(s);i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}


port = get_kb_item("Transport/SSL");
if(!port)port = 443;
if(!get_port_state(port))exit(0);


include ("ssl_funcs.inc");
include ("http_func.inc");



# Microsoft IIS, Netware, et al  check...DOH!
mymlen = 0;
mymtype = 0;
myversion = 15;
req=client_hello(mlen:mymlen, mtype:mymtype, version:myversion);
soc=open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) exit(0);
send (socket:soc, data:req);
r = recv(socket:soc, length:65535);
if (r)  exit(0);                    # eh? ... I set version == 15 ... did ya catch that?
close(soc);
# End Microsoft IIS, Netware, et al check....



req=client_hello(port:port);
soc=open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) exit(0);
send (socket:soc, data:req);     
r = recv(socket:soc, length:65535);
if (r) {
    localcert = hex2raw(s:"03CB0003C8308203C43082032DA003020102020100300D06092A864886F70D01010405003081A3310B30090603550406130255533112301006035504081309536F6D6553544154453111300F06035504071308536F6D654349545931173015060355040A130E4E6573737573205363616E6E6572311C301A060355040B1313536563757269747920436F6D706C69616E6365311430120603550403130B4E657373757320557365723120301E06092A864886F70D01090116116E6F6F6E65406E6F77686572652E636F6D301E170D3033313031303031313433395A170D3033313130393031313433395A3081A3310B30090603550406130255533112301006035504081309536F6D6553544154453111300F06035504071308536F6D654349545931173015060355040A130E4E6573737573205363616E6E6572311C301A060355040B1313536563757269747920436F6D706C69616E6365311430120603550403130B4E657373757320557365723120301E06092A864886F70D01090116116E6F6F6E65406E6F77686572652E636F6D30819F300D06092A864886F70D010101050003818D0030818902818100DCA93F62D5088026DBBAD24A551F136289E39CA34AD9C0EEE0493A7E3103884572ADE53ACE68416FAB0CE44F3291A71A7FA3B89E6490E622F61B71140FCA37F2C5C8AD0D96CF1DEC454960B70582918BE96C5DEEC5B2E2A58CC8506FEAE7941C5DA8AF2EF6225F903350AB54743F48FE3322D7383FD6B2B619D2045476C7C6550203010001A382010430820100301D0603551D0E04160414FA4DD1D034857B04784BCAA4A708E004F2DFCD063081D00603551D230481C83081C58014FA4DD1D034857B04784BCAA4A708E004F2DFCD06A181A9A481A63081A3310B30090603550406130255533112301006035504081309536F6D6553544154453111300F06035504071308536F6D654349545931173015060355040A130E4E6573737573205363616E6E6572311C301A060355040B1313536563757269747920436F6D706C69616E6365311430120603550403130B4E657373757320557365723120301E06092A864886F70D01090116116E6F6F6E65406E6F77686572652E636F6D820100300C0603551D13040530030101FF300D06092A864886F70D0101040500038181001214A295E71DAF8EEAB4A9E19499B98D766A02A1F62B1F388C635A8D2A08B3F678CF952ACE0D57F8C4510C2F22C3CB3EBAFEBBE8E3DAF83183898EAA27858D0CFB1B4121C3FE750EEC740FFF46452B90D5473200B7121343990B185CF8698A2115B62D57CFD9C9EA220054EF4CF49513C25B63B07C38D126F4CAF98B37EAB0EC");

    req2 = client_send_cert(certificate:localcert);
    send (socket:soc, data:req2);
    r2 = recv(socket:soc, length:65535);
    if (r2) {
        if ( ord(r2[6]) == 10) {                         # the 7th byte must == 0x0A which is an error
           exit(0);                                      # message stating "Unexpected message"
        } else {
           security_hole(port);
        }                                               
    } else {
       # well, we sent the cert and the server fin'ed or RST'ed...what to do, what to do...????
       # the cert was, after all, out of line...we should have gotten an error code 0x0A...so...
       security_hole(port);
    }
}
exit(0);

