var txt=document.smb.ta.value;
stxt=txt.split("smbmount_child");
q=stxt.length
  if (q>1) { document.getElementById('failed').style.display = 'none';   }
  else { document.getElementById('done').style.display = 'none';   }
