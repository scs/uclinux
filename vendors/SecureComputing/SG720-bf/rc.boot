#
# Prototype boot time rc.
# It loop mounts the image filesystem, and then starts it up properly.
#
echo
echo "SnapGear loop boot loading..."
echo
mount -t proc proc proc
mount /dev/hda1 /mnt1
mount -o loop /mnt1/v4.0.0b3/SG720-20080611.sgu /mnt2
cd /mnt2
pivot_root . oldroot
exec chroot . sh -c 'exec /bin/init'
