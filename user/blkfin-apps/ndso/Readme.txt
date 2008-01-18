Blackfin® Network Scope Readme v1.0                                                             
by Michael Hennerich                                                                            
hennerich@blackfin.uclinux.org                                                                  
                                                                                                
                                                                                                
The Network Scope, demonstrates a simple mechanism to share access and data distributed over    
a TCP/IP network. A web browser contacts the HTTP server running on Blackfin where the CGI      
program resides, and asks it to run the program. Parameters from the HTML form are passed to    
the program (parameters are passed through the Environment, or passed similar to command        
line arguments)The called program samples data from the ADC using a linux device driver         
(adsp-spiadc.c). Incoming samples are preprocessed and stored in a file. The CGI program then   
calls Gnuplot and requests to generate a PNG or JPEG image based on the sampled data and form   
settings. (Gnuplot is a portable command-line driven interactive datafile and function plotting 
utility). The server takes the output of the CGI program and returns it to the web browser.     
The web browser displays the output as an HTML page.
                                           
                                                                                                
In order to successfully build and run the Application following                                
kernel and user space adjustments needs to be done.                                             
                                                                                                
1) In your uClinux-dist folder enter:                                                              
                                                                                                
#make menuconfig                                                                                
                                                                                                
                                                                                                
         [ ] Default all settings (lose changes)                                                
         [*] Customize Kernel Settings (NEW)                                                    
         [*] Customize Vendor/User Settings (NEW)                                               
         [ ] Update Default Vendor Settings                                                     
                                                                                                
                                                                                                
  --- Processor                                                                                 
      CPU (BF533)  --->                                                                         
  --- Platform                                                                                  
      Platform (STAMP board support)  --->                                                      
        STAMP board support                                                                     
      Kernel executes from (RAM)  --->                                                          
  [*] Allow allocating large blocks (> 1MB) of memory                                           
  --- DMA Support                                                                               
      Select DMA driver (Enable Simple DMA Support)  --->                                       
  --- Cache Support                                                                             
                                                                                                
                                                                                                
Check Customize Kernel Settings and Customize Vendor/User Settings, then save and exit          
During kernel configuration under 'Processor type and features', Enable 'Simple DMA Support'.   
                                                                                                
In addition to that also check 'Blackfin BF533/2/1 ADSP SPI ADC support'                        
                                                                                                
                                                                                                
             [ ] Blackfin BF533/2/1 SPI port support                                            
             [*] Blackfin BF533/2/1 ADSP SPI ADC support                                        
             [ ] Blackfin BF533/2/1 Programmable Flags Driver                                   
             [ ] Virtual terminal                                                               
             [ ] Non-standard serial port support                                               
                 Serial drivers  --->                                                           
             [*] Unix98 PTY support                                                             
             [*] Legacy (BSD) PTY support                                                       
             (256) Maximum number of legacy PTY in use                                          
             [ ] QIC-02 tape support                                                            
                 IPMI  --->                                                                     
                 Watchdog Cards  --->                                                           
             [ ] Enhanced Real Time Clock Support                                               
             [ ] Generic /dev/rtc emulation                                                     
             [*] Blackfin Real Time Clock Support                                               
             [*] Blackfin Power Management support                                              
             [ ] Double Talk PC internal speech card support                                    
             [ ] Siemens R3964 line discipline                                                  
                 Ftape, the floppy tape device driver  --->                                     
             [ ] /dev/agpgart (AGP Support)                                                     
             [ ] Direct Rendering Manager (XFree86 4.1.0 and higher DRI support)                
             [ ] RAW driver (/dev/raw/rawN) (OBSOLETE)                                          
                                                                                                
                                                                                                
Save and exit. We are now leaving kernel configuration and enter user space configuration.      
Here we need to force build of libZ and libpng ('Library Configuration'), as well as enabling   
the 'Networked Software Defined Storage Oscilloscope' application under 'Blackfin app programs'.

                                                                                                
                           Core Applications  --->                                              
                           Library Configuration  --->                                          
                           Flash Tools  --->                                                    
                           Filesystem Applications  --->                                        
                           Network Applications  --->                                           
                           Miscellaneous Applications  --->                                     
                           BusyBox  --->                                                        
                           Tinylogin  --->                                                      
                           MicroWindows  --->                                                   
                           Games  --->                                                          
                           Miscellaneous Configuration  --->                                    
                           Debug Builds  --->                                                   
                           Blackfin test programs  --->                                         
                           Blackfin app programs  --->                                          
                                                                                                
                                                                                                
                       --- Force build (Normally built when required)                           
                       [ ] Build libAES                                                         
                       [ ] Build libDES                                                         
                       [ ] Build libSSL                                                         
                       [ ] Build libGMP                                                         
                       [ ] Build libG                                                           
                       [ ] Build libldap                                                        
                       [ ] Build libPAM                                                         
                       [ ] Build libPCAP                                                        
                       [*] Build libZ                                                           
                       [ ] Build libATM                                                         
                       [*] Build libpng                                                         
                       [ ] Build libjpeg                                                        
                       [ ] Build ncurses                                                        
                       --- Library Configuration                                                
                       [ ] Support time zones                                                   
                                                                                                
                                                                                                
                       [ ] gdbserver                                                            
                       [*] Networked Software Defined Storage Oscilloscope                      
                                                                                                
Save and exit

2) Recompile kernel and user space

3) Starting the Application:

From the shell:

    1.)	Configure Ethernet       : #ifconfig eth0 192.168.0.1
    2.)	Starting the Application : #ndso &

4) Accessing the Web User Interface:

Open a web browser (Mozilla Firefox, IE)
Enter in the URL window: http://192.168.0.1 
                                                                                   
                                                                                                