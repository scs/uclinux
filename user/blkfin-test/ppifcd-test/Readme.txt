/*
 *
 *    Rev:          $Id: Readme.txt 987 2005-07-18 10:13:16Z hennerich $
 *    Revision:     $Revision: 987 $
 *    Source:       $Source$  
 *    Created:      18.07.2005 12:06
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  Getting Started Readme file for PPIFCD driver  
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
                                                                                             
PPIFCD Frame Capture Driver test application  

The test application defaults to a Micron MT9M001 1.3 Megapixel CMOS digital imagine sensor. 
(1280 x 1024 pixels). In case you want to use this application with an different sensor, 
you have to do some slight modifications to the source code in ppifcd_test.c.
                                                                                                                                                            
In order to successfully build and run the PPIFCD Test Application, following                                
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
Here we need to enable 'PPIFCD test program' under 'Blackfin test programs'.

                                                                                                
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
			                [ ] PFLAGS test program       
			                [*] PPIFCD test program (NEW) 
                            [ ] Still to write                                                     
Save and exit

2) Recompile kernel and user space


3) STAMP board hardware modifications.

	-Populate R85 and R86 with 10k Resistors
	-Cut connection trace SCK-PF3 between pads of R67
	-Populate R65 with Zero Ohm Resistor or bridge 

Wire a camera module as shown in schematic_ppi_cmos_camera.pdf to the PPI.

4) Starting the test Application:


Usage: ppifcd_test [-h?vt] [-c count] [-r REG -a REGVALUE] [BMP output filename]
        -h?            this help
        -v             print version info
        -t             user trigger strobe to capture image
        -c count       repeat count times
        -r REG         I2C register
        -a VAL         I2C value


The test application defaults to a Micron MT9M001 1.3 Megapixel CMOS digital 
imagine sensor. (1280 x 1024 pixels). In case you want to use this application 
with an different sensor, you have to do some slight modifications to the source 
code in ppifcd_test.c.

5.) Starting the Application without arguments : ppifcd_test

This will read the current internal registers via I2C and calculate the timing.
Followed by a single frame capture. The actual “Total Frame Capture Time” may vary 
between once and twice a total frame time – depending when the command was issued, 
relative to the free running frame output of the camera module.     

root:~> ppifcd_test
************* Calculated Times Based on the actual Camera setting *************
Master Clock =          80 MHz
row_time =              1514 pixel clocks
total_frame_time =      1589700 pixel clocks
total_frame_time =      33118 usec
*******************************************************************************
Read Start:                     2344494852.825393
Read End:                       2344494852.867655
Total Frame Capture Time:       42257 usec

root:~>

6.)Starting the Application with count argument

This will read the current internal registers via I2C and calculate the timing.
Followed by capturing [count] frames. The actual “Total Frame Capture Time” 
for the first frame may vary between once and twice a total frame time – 
depending when the command was issued, relative to the free running frame 
output of the camera module. Any following frame will only take the total frame time, 
since the application is now synchronized and can capture the following frame 
from the beginning.    

root:~> ppifcd_test -c3
************* Calculated Times Based on the actual Camera setting *************
Master Clock =          80 MHz
row_time =              1514 pixel clocks
total_frame_time =      1589700 pixel clocks
total_frame_time =      33118 usec
*******************************************************************************
Read Start:                     2344492552.974414
Read End:                       2344492553.015973
Total Frame Capture Time:       41554 usec

Read Start:                     2344492553.016188
Read End:                       2344492553.049306
Total Frame Capture Time:       33119 usec

Read Start:                     2344492553.049499
Read End:                       2344492553.082644
Total Frame Capture Time:       33140 usec

root:~>

7.) Starting the Application with count and trigger argument

This will read the current internal registers via I2C and calculate the timing.
Followed by capturing [count] frames. The actual “Total Frame Capture Time” for the 
first and all following frames, is always twice the total frame time, 
and therefore suboptimal.  

root:~> ppifcd_test -c3 -t
************* Calculated Times Based on the actual Camera setting *************
Master Clock =          80 MHz
row_time =              1514 pixel clocks
total_frame_time =      1589700 pixel clocks
total_frame_time =      33118 usec
*******************************************************************************
Read Start:                     2344492707.654564
Read End:                       2344492707.720713
Total Frame Capture Time:       66144 usec

Read Start:                     2344492707.720928
Read End:                       2344492707.787068
Total Frame Capture Time:       66135 usec

Read Start:                     2344492707.787265
Read End:                       2344492707.853404
Total Frame Capture Time:       66134 usec
root:~>



8.) Starting the Application with output filename argument

Same as 5.) but will write the last received frame into a file specified by the filename 
argument. Always use/var as storage location. (/var is mounted to a 4MB ramdisk) 

root:~> ppifcd_test -c3 /var/img.bmp
************* Calculated Times Based on the actual Camera setting *************
Master Clock =          80 MHz
row_time =              1514 pixel clocks
total_frame_time =      1589700 pixel clocks
total_frame_time =      33118 usec
*******************************************************************************
Read Start:                     2344492748.564781
Read End:                       2344492748.609462
Total Frame Capture Time:       44676 usec

Read Start:                     2344492748.609677
Read End:                       2344492748.642799
Total Frame Capture Time:       33117 usec

Read Start:                     2344492748.643005
Read End:                       2344492748.676129
Total Frame Capture Time:       33119 usec

*******************************************************************************
Saved: /var/img.bmp
Size : 1311798
*******************************************************************************
root:~>


9.) Enhanced test and benchmarking options:

9.1) Capturing 1000 frames and displaying the CPU user and system utilization.

Start the application with the an imminent ‘time’ command and a count of 1000 frames. 

Result:

real    0m 33.43s
user    0m 0.11s
sys     0m 0.16s

1000 frames / 33.43s = 30 fps (frames per second)


root:~> time ppifcd_test -c1000
************* Calculated Times Based on the actual Camera setting *************
Master Clock =          80 MHz
row_time =              1514 pixel clocks
total_frame_time =      1589700 pixel clocks
total_frame_time =      33118 usec
*******************************************************************************
Read Start:                     2344493374.727110
Read End:                       2344493374.770163
Total Frame Capture Time:       43047 usec

Read Start:                     2344493374.770378
Read End:                       2344493374.803497
Total Frame Capture Time:       33113 usec
.
.
.
Read Start:                     2344493444.311419
Read End:                       2344493444.344561
Total Frame Capture Time:       33136 usec

Read Start:                     2344493444.344755
Read End:                       2344493444.377897
Total Frame Capture Time:       33136 usec

real    0m 33.43s
user    0m 0.11s
sys     0m 0.16s
root:~>


9.2) Running long time tests.


This will test following:

- ppifcd driver
- pflags driver
- I2C layer and drivers

root:~> watch -n 1 ppifcd_test /var/img.bmp

Every 1s: ppifcd_test /var/img.bmp      Thu Mar 12 01:35:14 1908

************* Calculated Times Based on the actual Camera setting *************
row_time =              1514 pixel clocks
total_frame_time =      1589700 pixel clocks
total_frame_time =      33118 usec
*******************************************************************************
Read Start:                     2344493010.655741
Read End:                       2344493010.705266
Total Frame Capture Time:       49520 usec

*******************************************************************************
Saved: /var/img.bmp
Size : 1311798
*******************************************************************************
root:~>

                                                                                   
                                                                                                
