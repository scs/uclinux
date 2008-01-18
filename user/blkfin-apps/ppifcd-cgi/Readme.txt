/*
 *
 *    Rev:          $Id: Readme.txt 990 2005-07-18 11:12:55Z hennerich $
 *    Revision:     $Revision: 990 $
 *    Source:       $Source$  
 *    Created:      18.07.2005 12:06
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  Getting Started Readme
 *                  
 *   Copyright (C) 2005 Michael Hennerich
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 ****************************************************************************  

PPIFCD-CGI Frame Capture Driver test application  
by Michael Hennerich                                                                            
hennerich@blackfin.uclinux.org 


The test application defaults to a Micron MT9M001 1.3 Megapixel CMOS digital imagine sensor. 
(1280 x 1024 pixels). In case you want to use this application with an different sensor, 
you have to do some slight modifications to the source code in fcd.c.
                                                                                                                                                            
In order to successfully build and run the PPIFCD-CGI Application, following                                
kernel and user space adjustments needs to be done.                                             
                                                                                                
1) In your uClinux-dist folder enter:                                                              
                                                                                                
#make menuconfig                                                                                
                                                                                                
                                                                                                
         [ ] Default all settings (lose changes)                                                
         [*] Customize Kernel Settings (NEW)                                                    
         [*] Customize Vendor/User Settings (NEW)                                               
         [ ] Update Default Vendor Settings                                                     
                                                                                                
                                                                                             
Check Customize Kernel Settings and Customize Vendor/User Settings, then save and exit          
During kernel configuration under 'Character devices', check 'Blackfin BF533/2/1 Programmable Flags Driver'
and 'Blackfin BF5xx PPI Camera frame capture driver'.   
                                                                                                
                                                                                                    
             [ ] Blackfin BF533/2/1 SPI port support                                            
             [ ] Blackfin BF533/2/1 ADSP SPI ADC support                                        
             [*] Blackfin BF533/2/1 Programmable Flags Driver                                   
             [*] Blackfin BF5xx PPI Camera frame capture driver
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



During kernel configuration under 'I2C support', check 'I2C support', 'I2C device interface'     
                                                                  
                                                                  
             [*] I2C support                                      
             [*]   I2C device interface                           
                   I2C Algorithms  --->                           
                   I2C Hardware Bus support  --->                 
                   Hardware Sensors Chip support  --->            
                   Other I2C Chip support  --->                   
             [ ]   I2C Core debugging messages                    
             [ ]   I2C Algorithm debugging messages               
             [ ]   I2C Bus debugging messages                     
             [ ]   I2C Chip debugging messages                    
                                                                  
                                                                  
Under 'I2C Hardware Bus support' check 'Generic Blackfin and HHBF533/561 development board I2C support'                                                                   
                                                                  
			[*] Generic Blackfin and HHBF533/561 development board I2C support
			    BFIN I2C SDA/SCL Selection  --->                              
			[ ] AMD 756/766                                                   
			[ ] AMD 8111                                                      
			[ ] ISA Bus support                                               
			[ ] Parallel port adapter (light)                                 
			[ ] NatSemi SCx200 ACCESS.bus                                     
                                                                  
                                                                  
Select under 'BFIN I2C SDA/SCL Selection' PF2 as SDA (Serial Data) and PF1 as SCL (Serial Clock)                                                                  
                                                                  
                                                                  
                        (2) SDA is PF[0:15]                       
                        (1) SCL is PF[0:15]                       

                                                                                                
                                                                                                
Save and exit. We are now leaving kernel configuration and enter user space configuration.      
Here we need to enable ' CGI based Test Application for the PPI Frame Capture Driver' under 'Blackfin app programs'.

                                                                                                
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
                                                                                                
                                                                                                
[ ] gdbserver                                                    
[ ] Networked Software Defined Storage Oscilloscope              
[*] CGI based Test Application for the PPI Frame Capture Driver  
--- Inetutils                                                    
[ ] rsh                                                          
[ ] rcp                                                          
[ ] rshd                                                                                                              
Save and exit

2) Recompile kernel and user space


3) STAMP board hardware modifications.

	-Populate R85 and R86 with 10k Resistors
	-Cut connection trace SCK-PF3 between pads of R67
	-Populate R65 with Zero Ohm Resistor or bridge 

Wire a camera module as shown in schematic_ppi_cmos_camera.pdf to the PPI.

4) Starting the test Application:

From the shell:

    1.)	Configure Ethernet       : #ifconfig eth0 192.168.0.1
    2.)	Starting the Application : #fcd &

4) Accessing the Web User Interface:

Open a web browser (Mozilla Firefox, IE)
Enter in the URL window: http://192.168.0.1
