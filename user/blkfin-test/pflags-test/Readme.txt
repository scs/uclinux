/*
 *
 *    Rev:          $Id: Readme.txt 780 2005-04-21 08:27:16Z hennerich $
 *    Revision:     $Revision: 780 $
 *    Source:       $Source$  
 *    Created:      Do Apr 21 11:02:09 CEST 2005
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  Getting Started Readme file for PFLAGS driver  
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
                                                                                             
In order to successfully build and run the PFLAGS Test Application, following                                
kernel and user space adjustments needs to be done.                                             
                                                                                                
1) In your uClinux-dist folder enter:                                                              
                                                                                                
#make menuconfig                                                                                
                                                                                                
                                                                                                
         [ ] Default all settings (lose changes)                                                
         [*] Customize Kernel Settings (NEW)                                                    
         [*] Customize Vendor/User Settings (NEW)                                               
         [ ] Update Default Vendor Settings                                                     
                                                                                                
                                                                                             
Check Customize Kernel Settings and Customize Vendor/User Settings, then save and exit          
During kernel configuration under 'Character devices', Blackfin BF533/2/1 Programmable Flags Driver'.   
                                                                                                
                                                                                                    
             [ ] Blackfin BF533/2/1 SPI port support                                            
             [ ] Blackfin BF533/2/1 ADSP SPI ADC support                                        
             [*] Blackfin BF533/2/1 Programmable Flags Driver                                   
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
Here we need to enable 'PFLAGS test program' under 'Blackfin test programs'.

                                                                                                
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
                                                                                                
                                                                                                
			                [ ] RTC test program   
			                [ ] DPMC test program  
			                [ ] AUDIO test program 
			                [ ] VIDEO test program 
			                [*] PFLAGS test program
			                [ ] Still to write     
                                                                                            
Save and exit

2) Recompile kernel and user space

3) Starting the Application:

From the shell:

    1.)	Starting the Application : pflags_test
    
root:~> pflags_test
########################## PFLAGS TEST ###############################
open success /dev/pf2
open success /dev/pf5


Press BTN1 to EXIT
root:~>

This will toggle STAMP board LED1 until Button1 is pressed.

4) Test PROC filesystem interface 

From the shell type: cat /proc/driver/pflags

root:~> cat /proc/driver/pflags
FIO_DIR         : = 0x1F
FIO_MASKA       : = 0x0
FIO_MASKB       : = 0x80
FIO_POLAR       : = 0x160
FIO_EDGE        : = 0x0
FIO_INEN        : = 0x1E0
FIO_BOTH        : = 0x0
FIO_FLAG_D      : = 0x1D
PIN     :DATA DIR INEN EDGE BOTH POLAR MASKA MASKB
        :H/L  O/I D/E  E/L  B/S   L/H   S/C   S/C
PF0     : 1....1....0....0....0....0.....0.....0
PF1     : 0....1....0....0....0....0.....0.....0
PF2     : 1....1....0....0....0....0.....0.....0
PF3     : 1....1....0....0....0....0.....0.....0
PF4     : 1....1....0....0....0....0.....0.....0
PF5     : 0....0....1....0....0....1.....0.....0
PF6     : 0....0....1....0....0....1.....0.....0
PF7     : 0....0....1....0....0....0.....0.....1
PF8     : 0....0....1....0....0....1.....0.....0
PF9     : 0....0....0....0....0....0.....0.....0
PF10    : 0....0....0....0....0....0.....0.....0
PF11    : 0....0....0....0....0....0.....0.....0
PF12    : 0....0....0....0....0....0.....0.....0
PF13    : 0....0....0....0....0....0.....0.....0
PF14    : 0....0....0....0....0....0.....0.....0
PF15    : 0....0....0....0....0....0.....0.....0
root:~>

                                                                                   
                                                                                                