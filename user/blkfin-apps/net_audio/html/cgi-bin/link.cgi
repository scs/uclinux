#!/bin/msh
echo Content-type: text/html
echo
FULLUSR=username=shiva
FULLPWD=password=isofttech
QUERY_STRING=//192.168.1.221/shiva
smbmount $QUERY_STRING /mnt -o $FULLUSR,$FULLPWD
echo "<center><br>Samba Mount : Done.<br></center>"

echo "<br></center></body></html>"

