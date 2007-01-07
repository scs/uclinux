#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 
 script_id(10481);  
 script_version ("$Revision: 1.19 $");

 name["english"] = "Unpassworded MySQL";
 name["francais"] = "MySQL sans mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script attempts to log into to the remote
MySQL daemon, and retrieves the list of the
databases installed on the remote host.

Risk factor : High";

	
 desc["francais"] = "
Ce script tente de se logguer dans le daemon MySQL distant
et d'en obtenir la liste des bases qu'il gère.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to log into the remote MySQL daemon";
 summary["francais"] = "Tente de se logger dans le daemon MySQL distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

debug=0; # darn inconsistant results flaky msql servers?
port = get_kb_item("Services/mysql");
if(!port)port = 3306;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
r1 = recv(socket:soc, length:1024);
if(strlen(r1) < 7)exit(0);
if (" is not allowed to connect to this MySQL" >< r1) exit(0);
if ("Access denied" >< r1)exit(0);
if ("is blocked because of many connection errors" >< r1) {
  security_note(port:port, data:"This MySQL server is temporarily refusing connections.\n");
  exit(0);
}

str = raw_string(0x0A, 0x00, 0x00, 0x01, 0x85, 0x04,
    	 	 0x00, 0x00, 0x80, 0x72, 0x6F, 0x6F, 0x74, 0x00);

send(socket:soc, data:str);
r1 = recv(socket:soc, length:4096);
if(!strlen(r1))exit(0);
expect = raw_string(0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00);

## note, you MIGHT get this:
##FHost 'www.nessus.org' is not allowed to connect to this MySQL
#serverConnection closed by foreign host.



l = strlen(r1);
k = 7; # normally 7 but could be less

 if(debug && !(l == 7)) display("len r1:",l,"\n");

if(l <= k) k = l; 

k=k-1;

if(debug) display("k:",k,"\n");

# k was 6 in original

ok = 1;


if(strlen(r1) < k)exit(0);

for(i=0;i<k;i=i+1)
{
  if(!(ord(r1[i])==ord(expect[i])))ok=0;
}
if(!ok){
	close(soc);
	exit(0);
	}
#
# Ask the databases
#
str = raw_string(0x0F, 0x00, 0x00, 0x00, 0x03) + "show databases";
send(socket:soc, data:str);
r = recv(socket:soc, length:2048);
close(soc);


skip = 11 + ord(r[10]) + 19;


#display(r);
dbs = "";
while(ok)
{
  len = ord(r[skip]);
#  display("len: ", len, "\n");
  db = "";
  if(strlen(r) < len)
  { 
   ok = 0;
  }
  else
  {
  for(i=0;i<len;i=i+1)
  {
    db = db + r[skip+1+i];
  }
 
  skip = skip + len + 5;
  len_r = strlen(r);
  len_r = len_r - 1;
  if(skip >= len_r)ok = 0;
  dbs = dbs + ". " + db + string("\n");
  }
}


report = string("Your MySQL database is not password protected.\n\n",
"Anyone can connect to it and do whatever he wants to your data\n",
"(deleting a database, adding bogus entries, ...)\n",
"We could collect the list of databases installed on the remote host :\n\n",
dbs,
"\n",
"Solution : Log into this host, and set a password for the root user\n",
"through the command 'mysqladmin -u root password <newpassword>'\n",
"Read the MySQL manual (available on www.mysql.com) for details.\n",
"In addition to this, it is not recommanded that you let your MySQL\n",
"daemon listen to request from anywhere in the world. You should filter\n",
"incoming connections to this port.\n\n",
"Risk factor : High");

security_hole(port:port, data:report);

