#
# Default Account
#
# This file implements (or will implement) various ways of determining if
# an account is valid
#
#
# $Id: default_account.inc,v 1.3 2003/03/13 00:15:28 renaud Exp $
#



#
# Private functions
# 



function _check_telnet(port, login, password)
{
 local_var soc, res;
 soc = open_sock_tcp(port);
 if(!soc)return(0);

 res = telnet_init(soc);
 res = string(res, recv(socket:soc, length:4096, timeout:3));
 if("ogin" >!< res) 
 {
 close(soc);
 return(0);
 }


send(socket:soc, data:string(login, "\r\n"));
res = recv_line(socket:soc, length:4096);
if(isnull(password) && ("word:" >< res))
{
 close(soc);
 return(0);
}
if(password)
{
 send(socket:soc, data:string(password, "\r\n"));
 res = recv_line(socket:soc, length:4096);
}

send(socket:soc, data:string("id\r\n"));
res = recv_line(socket:soc, length:4096);
while(res)
 {
 if("ogin incorrect" >< res)
 {
  close(soc);
  return(0);
 }

 
 if(egrep(pattern:"(uid=)|(Last login)", string:res))
 	{
 	close(soc);
 	return(1);
	}
  
 if("ogin:" >< res)
 {
  close(soc);
  return(0);
 }
 
 	
 res = recv_line(socket:soc, length:4096);
 }
 close(soc);
 return(0);
}

#-------------------------------------------------------------------#


function check_account(login, password)
{
 local_var port;
 
 port = get_kb_item("Services/telnet");
 if(!port) port = 23;
 
 if(get_port_state(port))
 {
  res = _check_telnet(port:port, login:login, password:password);
  if(res)
   return(port);
 }
 return(0);
}
