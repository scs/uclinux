#
#	FLASH handling code.
#

file

set $flash = 0xbe000000
set $ram   = 0xa0000000
set $ssize = 0x20000

define flash-id-16
set  * (((unsigned short *) $flash) + 0x00) = 0x00
set  * (((unsigned short *) $flash) + 0x55) = 0x98
printf "should get back 0x51 0x52 0x59\n"
shell sleep 1
p /x * (((unsigned short *) $flash) + 0x20)
p /x * (((unsigned short *) $flash) + 0x22)
p /x * (((unsigned short *) $flash) + 0x24)
set  * (((unsigned short *) $flash) + 0x00) = 0xf0
end

define flash-erase-real
set *((unsigned short *) $arg0) = 0x2020
set *((unsigned short *) $arg0) = 0xd0d0
shell sleep 2
set *((unsigned short *) $arg0) = 0xffff
shell sleep 0
end

define flash-erase
printf "ERASE: addr=%x", $arg0
	flash-erase-real ($arg0)
	flash-erase-real ($arg0+2)
printf "\n"
end


define flash-eraseall
set $addr = 0
while ($addr < 0x800000)
	flash-erase $flash+$addr
	set $addr = $addr + 0x20000
end
end


define flash-eraseimage
set $addr = 0xa0000
while ($addr < 0x800000)
	flash-erase $flash+$addr
	set $addr = $addr + 0x20000
end
end


define flash-eraseboot
flash-erase $flash
end

define flash-program-byte
set *((unsigned char *) $arg0) = 0x40
set *((unsigned char *) $arg0) = $arg1
set $delay = 0
while ($delay < 5)
	set $val = *((unsigned char *) $arg0)
	set $delay = $delay + 1
end
set *((unsigned char *) $arg0) = 0xff
end

define flash-program-short
#set *((unsigned short *) $arg0) = 0x4040
set *((unsigned short *) $arg0) = 0x1010

set *((unsigned short *) $arg0) = $arg1
set $delay = 0
while ($delay < 5)
	set $val = *((unsigned short *) $arg0)
	set $delay = $delay + 1
end
set *((unsigned short *) $arg0) = 0xffff
end

define flash-program-long
set *((unsigned short *) $arg0) = 0x4040
set *((unsigned long *) $arg0) = $arg1
set $delay = 0
#while ($delay < 5)
#	set $val = *((unsigned short *) $arg0)
#	set $delay = $delay + 1
#end
shell sleep 1
set *((unsigned short *) $arg0) = 0xffff
end

define load-flash-code
	# $2(v0) = dst ptr
	# $3(v1) = src ptr
	# $4(a0) = length (in words)
	# $5     = (0x40)
	# $6     = data being written
	# $7     = data-check
	# $8     = (0x50)
	# $9     = (0x80)
	# $10    = (0xff)
	#
	# li	$5, 0x40
	# li	$6, 0
	# li	$7, 0
	# li	$8, 0x50
	# li	$9, 0x80
	# li	$10,0xff
	# main_loop:
	# sh	$8,0($2)
	# sh	$5,0($2)
	# lhu	$6,0($3)
	# sh	$6,0($2)
	# wait_loop:
	# lhu	$7,0($2)
	# andi	$7,$7,0xffff
	# bne	$7,$9,wait_loop
	# nop
	# addiu	$4,$4,-1
	# addiu	$3,$3,2
	# addiu	$2,$2,2
	# bgtz	$4,main_loop
	# nop
	# break
	set *((unsigned long *)($ram+0x00)) = 0x24050040
	set *((unsigned long *)($ram+0x04)) = 0x24060000
	set *((unsigned long *)($ram+0x08)) = 0x24070000
	set *((unsigned long *)($ram+0x0c)) = 0x24080050
	set *((unsigned long *)($ram+0x10)) = 0x24090080
	set *((unsigned long *)($ram+0x14)) = 0x240a00ff

	# main_loop:
	set *((unsigned long *)($ram+0x18)) = 0xa4480000
	set *((unsigned long *)($ram+0x1c)) = 0xa4450000
	set *((unsigned long *)($ram+0x20)) = 0x94660000
	set *((unsigned long *)($ram+0x24)) = 0xa4460000
	#set *((unsigned long *)($ram+0x20)) = 0x8c660000
	#set *((unsigned long *)($ram+0x24)) = 0xac460000

	# wait_loop:
	set *((unsigned long *)($ram+0x28)) = 0x94470000
	set *((unsigned long *)($ram+0x2c)) = 0x30e7ffff
	set *((unsigned long *)($ram+0x30)) = 0x14e9fffd
	set *((unsigned long *)($ram+0x34)) = 0x00000000
	set *((unsigned long *)($ram+0x38)) = 0xa44a0000
	set *((unsigned long *)($ram+0x3c)) = 0x2484ffff
	set *((unsigned long *)($ram+0x40)) = 0x24630002
	set *((unsigned long *)($ram+0x44)) = 0x24420002
	set *((unsigned long *)($ram+0x48)) = 0x1c80fff3
	set *((unsigned long *)($ram+0x4c)) = 0x00000000
	set *((unsigned long *)($ram+0x50)) = 0x0000000d
	b *($ram+0x50)
	display /x $v0
	display /x $v1
	display /x $a0
end

define flash-boot
	# erase the flash
	flash-eraseboot
	x /2h $flash
	load-flash-code
	load boot/mips-boot-jtag.elf
	symbol-file boot/mips-boot-jtag.elf
	set $v0 = $flash
	set $v1 = $ram + 0x10000
	set $a0 = (((int)&_binary_boot128k_bin_size)/2)
	set $pc = $ram
	continue
	dump binary memory junk $flash ($flash+(int)&_binary_boot128k_bin_size)
	shell cmp -lb boot/boot128k.bin junk 
end

define flash-image
	# erase the image
	flash-eraseimage
	load-flash-code
	shell mips-linux-20070816-objcopy -I binary -O elf32-big images/image.bin images/image.o
	symbol-file images/image.o
	restore images/image.o ($ram+0x10000)
	set $v0 = $flash+0xa0000
	set $v1 = $ram + 0x10000
	set $a0 = (((int)&_binary_images_image_bin_size)/2)
	set $pc = $ram
	continue
end

define flash-all
	# erase the flash
	flash-eraseall
	x /2h $flash
	load-flash-code
	shell mips-linux-20070816-objcopy -I binary -O elf32-big images/flash.bin images/flash.o
	restore images/flash.o ($ram+0x10000)
	set $v0 = $flash
	set $v1 = $ram + 0x10000
	set $a0 = (((int)&_binary_images_flash_bin_size)/2
	set $pc = $ram
	continue
end

define uart-init
	set *(unsigned char *) 0xbd01110c = 0x83
	set *(unsigned char *) 0xbd011100 = 0x35
	set *(unsigned char *) 0xbd011104 = 0x0
	set *(unsigned char *) 0xbd01110c = 0x3
end

define uart-print
	set *(unsigned char *) 0xbd011100 = $arg0
end

define setup-cs
	# Setup the DRAM controller.
	# RAM is 2M x 16bit x 4banks = 16MB.
	# FLASH is 8MB.
	#set * (unsigned long *) 0xbd013000 = 0xd2b02000
	#set * (unsigned long *) 0xbd013004 = 0xffffffff
	#set * (unsigned long *) 0xbd013008 = 0xffffffff

	set * (unsigned long *) 0xbd013000 = 0xDAB02000
	set * (unsigned long *) 0xbd013004 = 0x1b1b1b00
	set * (unsigned long *) 0xbd013008 = 0x00000cea

	set $clk = * (unsigned long *) 0xbd01204c
	set * (unsigned long *) 0xbd01204c = (($clk & 0x88fffffc) | 0x04000000 | 0x2)
	#set * (unsigned long *) 0xbd01204c = (($clk & 0x88fffffc) | 0x04000000 | 0x3)
	#set * (unsigned long *) 0xbd01204c = (($clk & 0x88fffffc) | 0x00000000 | 0x2)
	#set * (unsigned long *) 0xbd01204c = (($clk & 0x88fffffc) | 0x01000000 | 0x2)
	#set * (unsigned long *) 0xbd01204c = (($clk & 0x88fffffc) | 0x00000000 | 0x1)
end

define load-vmlinux
	load linux-2.4.x/vmlinux
	symbol-file linux-2.4.x/vmlinux
	set $s0 = 0x00000000
	set $s1 = 0x00000000
	set $s2 = 0x00000000
	set $s3 = 0x00000000
	set $s4 = 0x00000000
end

define load-image
	load linux-2.4.x/vmlinux
	symbol-file linux-2.4.x/vmlinux
	set $s0 = 0x00000000
	set $s1 = 0x00000000
	set $s2 = 0x00000000
	set $s3 = 0x00000000
	set $s4 = 0x00000000
	shell mips-linux-20070816-objcopy -I binary -O elf32-big images/ramdisk images/ramdisk.o
	restore images/ramdisk.o &_end
end

#
# the SG310 spoecific stuff
#

set heur 0
set remoteti 10
#target mdi
target remote localhost:2345
set output-radix 16
set input-radix 16
set print pretty
set print asm-demangle
display /i $pc

uart-init
uart-print 'h'
uart-print 'e'
uart-print 'l'
uart-print 'l'
uart-print 'o'
uart-print '\n'

setup-cs

