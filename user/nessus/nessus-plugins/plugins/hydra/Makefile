include ../../nessus.tmpl

PLUGNAME=hydra

all : $(PLUGNAME).nes 

LO_OBJS = d3des.lo hydra4nessus.lo hydra-cisco.lo \
	hydra-ftp.lo hydra-http.lo hydra-icq.lo \
	hydra-imap.lo hydra-mod.lo hydra-nntp.lo \
	hydra-pcnfs.lo hydra-pop3.lo hydra-rexec.lo hydra-smb.lo \
	hydra-ldap.lo hydra-cisco-enable.lo \
	hydra-socks5.lo hydra-telnet.lo hydra-vnc.lo hydra.lo


d3des.lo : d3des.c 
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c d3des.c
	
hydra4nessus.lo : hydra4nessus.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra4nessus.c
	
hydra.lo : hydra.c
	$(LIBTOOL) $(CC) $(DEFS) -DNESSUS_PLUGIN $(include) -c hydra.c	
  	
hydra-cisco.lo : hydra-cisco.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-cisco.c
	
hydra-ftp.lo : hydra-ftp.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-ftp.c
	
hydra-http.lo : hydra-http.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-http.c	
			
hydra-icq.lo : hydra-icq.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-icq.c
	
hydra-imap.lo : hydra-imap.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-imap.c
	
hydra-mod.lo : hydra-mod.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-mod.c
	
hydra-nntp.lo : hydra-nntp.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-nntp.c			
				
hydra-pcnfs.lo : hydra-pcnfs.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-pcnfs.c
	
hydra-pop3.lo : hydra-pop3.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-pop3.c	
					
hydra-rexec.lo : hydra-rexec.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-rexec.c	
	
hydra-smb.lo : hydra-smb.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-smb.c
	
hydra-socks5.lo : hydra-socks5.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-socks5.c	
	
hydra-telnet.lo : hydra-telnet.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-telnet.c	
	
hydra-vnc.lo : hydra-vnc.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-vnc.c	
	
hydra-ldap.lo : hydra-ldap.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-ldap.c

hydra-cisco-enable.lo : hydra-cisco-enable.c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c hydra-cisco-enable.c
								
hydra.nes : $(LO_OBJS)
	$(LIBTOOL) $(CC) $(DEFS) -o libhydra.la $(LO_OBJS) $(LIBS) \
	-rpath $(rootdir)/bin/plugins
	../install_plug hydra $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o 
