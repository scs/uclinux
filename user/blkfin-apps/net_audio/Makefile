EXEC1 = smbmount.cgi 
EXEC2 = smbstatus.cgi
OBJS1 = smbmount.o 
OBJS2 = smbstatus.o

all: $(EXEC1) $(EXEC2)

$(EXEC1): $(OBJS1)
	$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDLIBS)
$(EXEC2): $(OBJS2)
	$(CC) $(LDFLAGS) -o $@ $(OBJS2) $(LDLIBS)

romfs:
	chmod 777 html/cgi-bin/*.cgi 
	$(ROMFSINST) /home/httpd/www/html 
	$(ROMFSINST) /etc/boa.conf
	$(ROMFSINST) -e CONFIG_USER_NET_AUDIO /home/httpd/www/html/cgi-bin/$(EXEC1)
	$(ROMFSINST) -e CONFIG_USER_NET_AUDIO /home/httpd/www/html/cgi-bin/$(EXEC2)

clean:
	-rm -f $(EXEC1) $(EXEC2) *.gdb *.elf *.o

