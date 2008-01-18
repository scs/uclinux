#!/bin/msh
echo Content-type: text/html
echo

echo "shiva:start mounting"
smbmount //192.168.1.221/shiva /mnt -o username=shiva,password=isofttech
echo "shiva:mounting done"
echo "<center><br>Samba Mount : Done.<br></center>"

echo "<br></center></body></html>"

