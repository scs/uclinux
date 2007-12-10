#!/bin/sh

INST=/tmp/uclinux-srv1

[ -e $INST ] || mkdir $INST

cp ../../../images/uImage.ext2 $INST
cp README $INST

cat << EOF >$INST/.gdbinit
target remote :2000

define uimage
	restore uImage.ext2 binary 0x1000000
end

echo Copying uImage to target SDRAM...
uimage

echo Now you can either:\n
echo - boot the image via "bootm"\n
echo - copy to eeprom via "eeprom write 0x1000000 0x20000 <size in bytes>"\n

detach
quit
EOF

cat << EOF >$INST/runme.sh
bfin-elf-gdb
EOF

[ -e $INST/camera_test ] || mkdir $INST/camera_test

cp -r ../../../user/blkfin-test/camera_test/Makefile $INST/camera_test
cp -r ../../../user/blkfin-test/camera_test/*.c $INST/camera_test

chmod a+x $INST/runme.sh
cd $INST/.. ; tar cfz uclinux-srv1.tgz uclinux-srv1
