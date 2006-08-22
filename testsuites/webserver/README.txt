This directory contains three parts:
1. Funkload. User can download the file funkload-1.4.0.tar.tar to install the funkload.
2. Funkload testcase,which locates in testcase/simple.
3. Test webpages, which locates in testcase/test.
-----------------
Install Funkload:
1. Download funkload-1.4.0.tar.gz to ~/ . You can find the latest funkload package form http://funkload.nuxeo.org .
2. tar -zxvf funkload-1.4.0.tar.gz. You will find a new directory ~/funkload-1.4.0.
3. > cd funkload-1.4.0
   > sudo python ez_setup.py  #install easy_install. It needs python-devel installed and setuptools.
   > cd funkload
   > sudo easy_install -U funkload
-----------------
Checkout test case and webpages
1. CVS update the testcase and test webpages to your machine.
-----------------
Change server configures:
1. > cd testsuites/webserver/testcase/simple
   > vi Simple.conf
2.meaning of some parameters:
 1) serverip=10.99.22.123
    Serer IP address. Change to your server IP.
 2) url=http://10.99.22.123/test
    The server URL to test. Change to your url.Just replace the IP with your server IP,don't change the /test directory. This /test is the default location of test webpages.
 3) nb_time=1000
    The times the test executes. Change to times you wanted.
 4) pages=/index.html:/BlackfinUboot.htm:/BlackfinuClinux.htm
    List of page separated by ':'.  Here are three pages.
 5) sleep_time_min = 0
    Sleeptime_min = minimu amount of time in seconds to sleep between requests to the host.
 6) sleep_time_max = 5
    Sleeptime_max = maximum amount of time in seconds to sleep between requests to the host.
    The time between the continous requests is a random time between sleep_time_min and sleep_time_max.
-----------------
Run webserver test:
On server:
1. Boot you BF5xx-xxxxx board.
2. > dhcpcd &
3. > rshd &       # We use rcp to copy the test web[ages.
4. > boa -c /etc &    # we now test boa web server
On client:
1. > cd testsuites/webserver/testcase/simple
   > fl-run-test test_Simple.py
