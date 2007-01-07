#
# This script was written by Patrik Karlsson <patrik.karlsson@ixsecurity.com>
#
#

if(description)
{
    script_id(10747);
    script_version("$Revision: 1.8 $");
   name["english"] = "3Com Superstack II switch with default password";
   name["francais"] = "3Com Superstack II switch avec mot de passe defaut";
   script_name(english:name["english"]);
 
   desc["english"] = "
The 3Com Superstack II switch has the default passwords set.

The attacker could use these default passwords to gain remote
access to your switch and then reconfigure the switch. These
passwords could also be potentially used to gain sensitive
information about your network from the switch.

Solution : Telnet to this switch and change the default passwords
immediately.

Risk factor : High";

 desc["francais"] = "
Le 3Com Superstack II switch a le mot de passe par default.

Un pirate peut se connecter et reconfigurer votre switch et resau.

Solution : faites un telnet a ce switch et changez le mot de
passe immédiatement

Facteur de risque : Elevé";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into 3Com Superstack II switches with default passwords";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001 Patrik Karlsson");
   script_family(english:"Misc.", francais:"Divers");
   script_require_ports(23);
 
   exit(0);
}

port = 23; # the port can't be changed

login[0] = string("monitor");
login[1] = string("manager");
login[2] = string("security");
bfound = 0;

res = string("Standard passwords were found on this 3Com Superstack switch.\n");
res = res + string("The passwords found are:\n\n");

if(get_port_state(port))
{

 for ( i=0; i<3; i = i + 1 )
 {
     soc = open_sock_tcp(port);
     if(soc)
     {
        send(socket:soc, data:string("foo\r\n"));
        r = recv(socket:soc, length:160);
        if("Login: " >< r)
        {
	    tmp = string(login[i], "\r\n");
	    send(socket:soc, data:tmp);
	    r = recv_line(socket:soc, length:2048);
	    send(socket:soc, data:tmp);
	    r = recv(socket:soc, length:2048);

	    if ( "logout" >< r )
	    {
		bfound = 1;
		res = string(res, login[i], ":", login[i], "\n");
     	    }

        }
   
      close(soc);

  }

 }

 res = string(res, "\nSolution : Telnet to this switch immediately and ",
 		  "change the passwords above.\n",
 		  "Risk factor : High\n");

 if ( bfound == 1 )
 {
      security_hole(port:23, data:res);
 }
}
