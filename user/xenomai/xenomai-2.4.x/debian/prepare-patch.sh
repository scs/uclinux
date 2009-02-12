#! /bin/bash

#----------------------------------------------------------------------
# Description: Hacked down & butchered scripts/prepare-kernel.sh..
#               Script to copy assorted sources to a temp directory and
#               generate a kernel patch without the need of a virgin
#               linux source tree.
#----------------------------------------------------------------------

set -e

unset CDPATH

patch_file=xenomai_all.patch

supported_arch="$*"

patch_append() {
    file="$1"

#    echo "diff -u1wbr orig/$file new/$file" >> $patch_file
    echo "--- linux/$file	1970-01-01 01:00:00.000000000 +0100" >> $patch_file
    echo "+++ linux-patched/$file	2007-03-06 17:55:58.000000000 +0000" >> $patch_file
    echo "@@ -500,0 +500,2 @@" >> $patch_file
    echo "+" >> $patch_file
    cat >> $patch_file
}

patch_link() {
    recursive="$1"              # "r" or "n"
    link_makefiles="$2"         # "m" or "n"
    target_dir="$3"
    link_dir="$4"

    (
        recursive_opt=""
        directorytype_opt=""
        if test x$recursive = xr; then
            recursive_opts="-mindepth 1"
            directorytype_opt="-type d -o"
        else
            recursive_opt="-maxdepth 1"
        fi
        link_makefiles_opt=""
        if test x$link_makefiles = xm; then
            link_makefiles_opt="-name Makefile -o"
        fi

        cd $xenomai_root/$target_dir &&
        find . $recursive_opt \( $link_makefiles_opt -name Kconfig -o -name '*.[chS]' \) |
        while read f; do
            f=`echo $f | cut -d/ -f2-`
            d=`dirname $f`
            if test ! -d  $temp_tree/$link_dir/$d ; then
                mkdir -p $temp_tree/$link_dir/$d
            fi
            cp $xenomai_root/$target_dir/$f $temp_tree/$link_dir/$f
        done
    )

}

generate_patch() {
    (
    cd "$temp_tree"
    find . -name demos -o -name snippets -exec rm -fR {} \+ &&
    find . -type f |
    while read f ; do
        diff -Naurd "$linux_tree/$f" "$f" |
        sed -e "s,^--- ${linux_tree}/\.\(/.*\)$,--- linux\1," \
            -e "s,^+++ \.\(/.*\)$,+++ linux-patched\1,"
    done
    )
}

diff_addons() {
    lines=`(echo ; echo ; cat $xenomai_root/scripts/Kconfig.frag) | wc -l`

    echo "--- linux/arch/$linux_arch/Kconfig	1970-01-01 01:00:00.000000000 +0100" >> $patch_file
    echo "+++ linux-patched/arch/$linux_arch/Kconfig	2007-03-06 17:55:58.000000000 +0000" >> $patch_file
    echo "@@ -40,2 +40,$lines @@" >> $patch_file
    echo " source \"init/Kconfig\"" >> $patch_file
    sed -e "s,@LINUX_ARCH@,$linux_arch,g" $xenomai_root/scripts/Kconfig.frag | sed 's/^/+/' >> $patch_file
    echo " " >> $patch_file
}

xenomai_root=`dirname $0`/..
xenomai_root=`cd $xenomai_root && pwd`

rm -fR $xenomai_root/tmp
rm -f $patch_file

mkdir -p $xenomai_root/tmp/linux
mkdir -p $xenomai_root/tmp/linux.new
linux_tree="$xenomai_root/tmp/linux"
temp_tree="$xenomai_root/tmp/linux.new"


for linux_arch in $supported_arch ; do
    case $linux_arch in
        i386)
            base_arch=x86
            ;;
        x86_64)
            base_arch=x86
            ;;
        x86)
            base_arch=x86
            ;;
        *)
            base_arch=$linux_arch
            ;;
    esac

    patch_link r m ksrc/arch/$base_arch arch/$linux_arch/xenomai
    patch_link r n include/asm-$base_arch include/asm-$linux_arch/xenomai

    p="+drivers-\$(CONFIG_XENOMAI)		+= arch/$linux_arch/xenomai/"
    echo $p | patch_append arch/$linux_arch/Makefile
    diff_addons
done

p="+obj-\$(CONFIG_XENOMAI)		+= xenomai/"
echo $p | patch_append drivers/Makefile

p="+obj-\$(CONFIG_XENOMAI)		+= xenomai/"
echo $p | patch_append kernel/Makefile

# Create local directories then symlink to the source files from
# there, so that we don't pollute the Xenomai source tree with
# compilation files.
patch_link n m ksrc/ kernel/xenomai
patch_link n m ksrc/arch kernel/xenomai/arch
patch_link r m ksrc/arch/generic kernel/xenomai/arch/generic
patch_link n m ksrc/nucleus kernel/xenomai/nucleus
patch_link r m ksrc/skins kernel/xenomai/skins
patch_link r m ksrc/drivers drivers/xenomai
patch_link r n include/asm-generic include/asm-generic/xenomai
patch_link n n include include/xenomai
cd $xenomai_root
for d in include/* ; do
    if test -d $d -a -z "`echo $d | grep '^include/asm-'`"; then
        destdir=`echo $d | sed -e 's,^\(include\)\(/.*\)$,\1/xenomai\2,'`
        patch_link r n $d $destdir
    fi
done

generate_patch >> $patch_file

cd $xenomai_root

#echo "Patch-name: Xenomai realtime kernel patches" > $xenomai_root/debian/linux-patch-xenomai.kpatches
#echo "Patch-id: xenomai" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
#echo "Architecture: all" >> $xenomai_root/debian/linux-patch-xenomai.kpatches

find $xenomai_root/ksrc/ -name "adeos-ipipe-2.6.*-$supported_arch-*.patch" |
while read f ; do

    file=`basename $f`
    arch=`echo $file | cut -d- -f4`
    kver=`echo $file | cut -d- -f3`

    case $arch in
        arm)
            march=arm
        ;;
        i386)
            march=i386
        ;;
        ia64)
            march=ia64
        ;;
        ppc|ppc64|powerpc)
            march=powerpc
        ;;
        x86_64)
            march=amd64
        ;;
	x86)
	    march=i386
	;;
    esac

    # Only one patch per arch/kver - Having a common plus kver/arch patch
    # would require two linux-patch-foo packages.. When dh-kpatches Ver.1.0
    # gets to testing, this can be looked at again..
    echo "" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
    echo "Patch-file: $file" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
    echo "Kernel-version: $kver" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
    echo "Architecture: $march" >> $xenomai_root/debian/linux-patch-xenomai.kpatches

    if [ "$arch" = "x86" ] ; then
	echo "" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
	echo "Patch-file: $file" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
	echo "Kernel-version: $kver" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
	echo "Architecture: amd64" >> $xenomai_root/debian/linux-patch-xenomai.kpatches
    fi

    cp $f $xenomai_root/$file
    cat $xenomai_root/$patch_file >> $xenomai_root/$file

done

exit 0

