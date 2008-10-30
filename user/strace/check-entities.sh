#!/bin/sh
#
# Usage: check.sh [strace version] [strace arch] [kernel arch]

usage()
{
	cat <<-EOF
	Usage: check-entities.sh [options] [kernel dir] [kernel arch] [strace dir] [strace arch]

	Options:
	  -k,--keep    Keep generated files
	  -h,--help    This help
	EOF
	if [ -n "$*" ] ; then
		printf "\nError: %s\n" "$*" 1>&2
		exit 1
	else
		exit 0
	fi
}

keep=false
while [ -n "$1" ] ; do
	case $1 in
		-h|--help) usage;;
		-k|--keep) keep=true;;
		-*) usage "Unknown option '$1'";;
		*)  break;;
	esac
	shift
done

# find the kernel source tree
if [ -z "$1" ] ; then
	ksrc="/usr/src/linux"
else
	ksrc="$1"
fi

# find the kernel arch
if [ -z "$2" ] ; then
	karch=$(uname -m)
else
	karch="$2"
fi

# find the strace source tree
if [ -z "$3" ] ; then
	if [ -e "strace.c" ] ; then
		ssrc="."
	elif [ -e "../strace.c" ] ; then
		ssrc=".."
	else
		ssrc=$(ls -d strace-* | sort | tail -n 1)
	fi
	if [ -z "$ssrc" ] ; then
		echo "unable to find strace source tree" 1>&2
		exit 1
	fi
else
	ssrc="$3"
fi

# find the strace arch
if [ -z "$4" ] ; then
	sarch=${karch}
else
	sarch="$4"
fi

# sanity check the strace source
for f in errno linux/ioctl signal syscall ; do
	f="${f}ent.sh"
	if [ ! -e "${ssrc}/${f}" ] ; then
		echo "Could not locate strace file '${f}' in '${ssrc}'" 1>&2
		echo " ... did you give correct strace path ?" 1>&2
		exit 1
	fi
done

# sanity check the kernel source
for d in include include/linux ; do
	if [ ! -d "${ksrc}/${d}" ] ; then
		echo "Could not locate kernel dir '${d}' in '${ksrc}'" 1>&2
		echo " ... did you give correct kernel path ?" 1>&2
		exit 1
	fi
done

# some helper funcs
get_header() {
	if [ -e linux/$sarch/$1 ] ; then
		echo linux/$sarch/$1
	else
		echo linux/$1
	fi
}
ebegin() { printf "$* ... "; }
eend()
{
	local lret=$1 header=$2
	shift
	if [ ${lret} -eq 0 ] ; then
		echo "OK!"
		${keep} || rm -f "$@"
	else
		echo "FAIL! (see ${PWD}/${header})"
	fi
	((ret+=${lret}))
}

# let's get goin!
echo "Strace: $sarch in $ssrc"
echo "Kernel: $karch in $ksrc"
cd "${ssrc}"

ret=0

[ -d "$ksrc/arch/$karch/include/asm" ] \
	&& arch_inc="$ksrc/arch/$karch/include/asm" \
	|| arch_inc="$ksrc/include/asm-$karch"

# easy: output is exactly what we want
ebegin "errno list"
sh ./errnoent.sh "$ksrc/include/linux"/*errno*.h "$ksrc/include/asm-generic"/*errno*.h "$arch_inc"/*errno*.h > errnoent.h
cmp -s errnoent.h $(get_header errnoent.h)
eend $? errnoent.h

# painful: need to extract the list of ioctls, then use gcc to turn
# it into a list of actual numbers, and then only complain when new
# ioctls have been *added*.  we'll keep around the old ones forever
# in case someone runs an old binary with the old ioctl.
ebegin "ioctl list"
sh ./linux/ioctlent.sh "$ksrc/include" "$arch_inc" | grep -v '^Looking for '
${BUILD_CC:-${CC:-gcc}} -E -dD -I. -Wall linux/ioctlsort.c -o ioctlsort.i
${BUILD_CC:-${CC:-gcc}} -Wall ioctlsort.i -o ioctlsort
./ioctlsort > ioctlent.h
! diff -u ioctlent.h $(get_header ioctlent.h) | sed 1,2d | grep -qs '^\-'
eend $? ioctlent.h ioctlsort ioctlsort.i ioctls.h ioctldefs.h

# easy: output is exactly what we want
ebegin "signal list"
sh ./signalent.sh "$arch_inc/signal.h" > signalent.h
cmp -s signalent.h $(get_header signalent.h)
eend $? signalent.h

# slightly painful: the generated list will required information such as number
# of args a function takes or how to interpret the parameters.  just compare
# the number of syscalls found as we'll assume that the syscall list is forever
# locked in stone and thus will only ever increase over time.
ebegin "syscall list"
sh ./syscallent.sh "$arch_inc/unistd.h" > syscallent.h
knr=$(set -- $(wc -l syscallent.h); echo $1)
snr=$(grep '^[[:space:]]{' $(get_header syscallent.h) | wc -l)
[ ${knr} -eq ${snr} ]
eend $? syscallent.h

exit ${ret}
